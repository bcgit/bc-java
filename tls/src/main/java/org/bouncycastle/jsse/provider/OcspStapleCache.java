package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;

/**
 * The OCSP responses a server has available to staple, and the rules for how long each one may be
 * reused.
 * <p/>
 * A stapling server fetches on behalf of whoever connects to it, so the cache is what keeps the
 * feature from turning an unauthenticated client into a lever on the server's outbound network:
 * <ul>
 * <li>responses are held on strong references in a bounded LRU map, so a hit is a hit - not
 * something a garbage collection can take away;</li>
 * <li>one fetch is in flight per certificate at a time, and concurrent callers wait for it rather
 * than starting their own;</li>
 * <li>a failure is remembered briefly, so an unreachable responder costs one attempt per
 * <code>failureLifetime</code> rather than one per handshake;</li>
 * <li>a caller's wait is bounded by <code>responseTimeout</code> - one waiting for another's fetch
 * exactly, one performing the fetch to within a read already in flight (see
 * {@link OcspStapleHttpFetcher}). A handshake never fails for want of a staple - stapling is an
 * optimisation, and its absence is not an error.</li>
 * </ul>
 * Reuse follows RFC 6960 sec. 4.2.2.1: a response is reused only while it is within both the
 * responder's stated nextUpdate and our own <code>cacheLifetime</code>, and a response stating no
 * nextUpdate ("newer revocation information is available all the time") is relayed once but never
 * cached. A response dated in the future by more than {@link #MAX_CLOCK_SKEW_MS} is treated as
 * unreliable and not stapled at all.
 */
class OcspStapleCache
{
    private static final Logger LOG = Logger.getLogger(OcspStapleCache.class.getName());

    private static final int DEFAULT_CACHE_SIZE = 256;
    private static final int DEFAULT_CACHE_LIFETIME = 3600;      // seconds
    private static final int DEFAULT_RESPONSE_TIMEOUT = 5000;    // milliseconds
    private static final int DEFAULT_FAILURE_LIFETIME = 60;      // seconds

    /**
     * Tolerance between our clock and the responder's when judging whether a response is dated in
     * the future. 15 minutes, matching what the JDK's own OCSP client allows.
     * <p/>
     * NOTE: keep in step with the CertPath validator's OcspCache.MAX_CLOCK_SKEW_MS.
     */
    static final long MAX_CLOCK_SKEW_MS = 15 * 60 * 1000L;

    /**
     * Build a cache configured from the system properties. The <code>jdk.tls.stapling.*</code> names
     * and defaults are the JDK's, so a deployment already tuned for the SunJSSE server does not have
     * to be retuned for this one: cacheSize 256, cacheLifetime 3600 seconds, responseTimeout 5000
     * milliseconds, responderOverride off, and a cache setting of exactly zero meaning "no limit of
     * this kind" rather than "no caching". Only zero: each of the numeric properties is read over a
     * range that excludes a negative value, so a negative one is refused with a warning and the
     * default used in its place, as it is for a value that is not a number at all.
     * <p/>
     * Two differences from SunJSSE, both deliberate:
     * <ul>
     * <li><code>ignoreExtensions</code> defaults to true here (see below);</li>
     * <li>a response stating no nextUpdate is never cached, whereas SunJSSE holds one for
     * cacheLifetime. RFC 6960 sec. 4.2.2.1 has an absent nextUpdate mean newer information is
     * available all the time, and the CertPath validator side of this library reads it the same
     * way.</li>
     * </ul>
     */
    static OcspStapleCache create(JcaJceHelper helper)
    {
        int cacheSize = PropertyUtils.getIntegerSystemProperty("jdk.tls.stapling.cacheSize",
            DEFAULT_CACHE_SIZE, 0, Integer.MAX_VALUE);
        int cacheLifetime = PropertyUtils.getIntegerSystemProperty("jdk.tls.stapling.cacheLifetime",
            DEFAULT_CACHE_LIFETIME, 0, Integer.MAX_VALUE);
        /*
         * Minimum 1, unlike the cache settings, where zero means "no limit of this kind": this bound
         * applies to a handshake thread, and a fetch that may take forever is not something to let an
         * operator configure by accident. A zero is refused with a warning and the default used
         * instead.
         */
        int responseTimeout = PropertyUtils.getIntegerSystemProperty("jdk.tls.stapling.responseTimeout",
            DEFAULT_RESPONSE_TIMEOUT, 1, Integer.MAX_VALUE);
        int failureLifetime = PropertyUtils.getIntegerSystemProperty(
            "org.bouncycastle.jsse.server.stapling.failureLifetime", DEFAULT_FAILURE_LIFETIME, 0,
            Integer.MAX_VALUE);

        /*
         * Unlike the JDK, this defaults to true. The extensions in question are the client's to
         * choose, and a nonce among them makes every response single-use - so honouring them turns
         * each handshake into an outbound OCSP request, which is exactly what the cache exists to
         * prevent. RFC 6066 sec. 8 has the client naming "OCSP request extensions the client wishes
         * the server to include", not extensions the server owes it. Set the property to false for
         * JDK parity - which forwards the nonce, and only the nonce; see
         * {@link #getStapledResponse(X509Certificate, X509Certificate, Extensions)}.
         */
        boolean ignoreExtensions = PropertyUtils.getBooleanSystemProperty(
            "jdk.tls.stapling.ignoreExtensions", true);

        URI responderOverride = null;
        if (PropertyUtils.getBooleanSystemProperty("jdk.tls.stapling.responderOverride", false))
        {
            String responderUri = PropertyUtils.getStringSystemProperty("jdk.tls.stapling.responderURI");
            if (null != responderUri && responderUri.length() > 0)
            {
                try
                {
                    responderOverride = new URI(responderUri);
                }
                catch (Exception e)
                {
                    LOG.log(Level.WARNING, "Ignoring unusable jdk.tls.stapling.responderURI: " + responderUri, e);
                }
            }
        }

        OcspStapleFetcher fetcher = new OcspStapleHttpFetcher(responderOverride, responseTimeout);

        return new OcspStapleCache(helper, fetcher, cacheSize, cacheLifetime * 1000L,
            failureLifetime * 1000L, responseTimeout, ignoreExtensions);
    }

    private final JcaJceHelper helper;
    private final OcspStapleFetcher fetcher;
    private final int cacheSize;
    private final long cacheLifetimeMs;
    private final long failureLifetimeMs;
    private final long responseTimeoutMs;
    private final boolean ignoreExtensions;
    private final AlgorithmIdentifier certIDDigestAlgorithm;

    private final Map<CertID, CacheEntry> cache = new LinkedHashMap<CertID, CacheEntry>(16, 0.75f, true)
    {
        protected boolean removeEldestEntry(Map.Entry<CertID, CacheEntry> eldest)
        {
            return cacheSize > 0 && size() > cacheSize;
        }
    };

    private final Map<CertID, Pending> pending = new HashMap<CertID, Pending>();

    // the certificates a nonced - and so uncacheable, and unshareable - fetch is in flight for
    private final Set<CertID> pendingNonced = new HashSet<CertID>();

    /**
     * @param cacheSize         most responses to hold, or zero or less for no limit.
     * @param cacheLifetimeMs   longest a response may be reused for, independently of its stated
     *                          nextUpdate; zero or less leaves nextUpdate as the only bound.
     * @param failureLifetimeMs how long a failed lookup suppresses further attempts for the same
     *                          certificate.
     * @param responseTimeoutMs longest a caller will wait for a response; must be positive.
     * @param ignoreExtensions  whether to drop the OCSP request extensions the client asked for.
     *                          When cleared, the client's nonce - and only its nonce - is forwarded.
     */
    OcspStapleCache(JcaJceHelper helper, OcspStapleFetcher fetcher, int cacheSize, long cacheLifetimeMs,
        long failureLifetimeMs, long responseTimeoutMs, boolean ignoreExtensions)
    {
        this.helper = helper;
        this.fetcher = fetcher;
        this.cacheSize = cacheSize;
        this.cacheLifetimeMs = cacheLifetimeMs;
        this.failureLifetimeMs = failureLifetimeMs;
        this.responseTimeoutMs = responseTimeoutMs;
        this.ignoreExtensions = ignoreExtensions;
        this.certIDDigestAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
    }

    /**
     * The response to staple for one certificate, from the cache where one is held and current, by
     * asking the responder otherwise.
     * <p/>
     * Of the request extensions a client may ask to have forwarded, only
     * <code>id-pkix-ocsp-nonce</code> ever is, and only when <code>ignoreExtensions</code> is
     * cleared. The rest are dropped: a response tailored to one client's extensions would otherwise
     * be cached under the certificate alone and relayed to clients that asked with different ones,
     * and none of them are extensions this server can meaningfully promise anyway.
     *
     * @param cert              the certificate to obtain status for.
     * @param issuer            its issuer, needed to identify it to the responder.
     * @param requestExtensions OCSP request extensions the client asked for, or null.
     * @return the response, or null when there is nothing to staple. Never throws: a caller is
     *         mid-handshake and has no better answer to a failure here than sending no staple.
     */
    OCSPResponse getStapledResponse(X509Certificate cert, X509Certificate issuer,
        Extensions requestExtensions)
    {
        CertID certID = createCertID(issuer, cert.getSerialNumber());
        if (null == certID)
        {
            return null;
        }

        Extensions nonce = ignoreExtensions ? null : getNonce(requestExtensions);

        OcspStaple staple = null == nonce
            ?   getCacheableStaple(certID, cert)
            :   getNoncedStaple(certID, cert, nonce);

        return null == staple ? null : staple.getResponse();
    }

    /**
     * The ordinary path: a response for the extension-free request every client shares, served from
     * the cache when one is held and fetched at most once at a time otherwise.
     */
    private OcspStaple getCacheableStaple(CertID certID, X509Certificate cert)
    {
        CacheEntry entry = getCurrentEntry(certID);
        if (null != entry)
        {
            if (null == entry.staple)
            {
                if (LOG.isLoggable(Level.FINER))
                {
                    LOG.finer("Recent OCSP failure recorded; not stapling for certificate: "
                        + cert.getSubjectX500Principal());
                }
                return null;
            }

            if (LOG.isLoggable(Level.FINER))
            {
                LOG.finer("Stapling cached OCSP response for certificate: "
                    + cert.getSubjectX500Principal());
            }
            return entry.staple;
        }

        return fetchSingleFlight(certID, cert);
    }

    /**
     * A response answering a client's nonce is good for that one request, so it is neither served
     * from the cache nor put into it - and a failed one says nothing about the shared request the
     * other clients use, so it is not recorded as a failure either. What does apply is the failure
     * entry as a <em>reader</em> (a responder that just failed the shared request is not worth
     * dialling again on someone's behalf) and a cap of one nonced fetch in flight per certificate,
     * so a client cannot turn concurrent handshakes into concurrent outbound requests.
     * <p/>
     * Sequential nonced handshakes do still cost one outbound request each. That is inherent to
     * forwarding a nonce - a fresh nonce demands a fresh response - and is why
     * <code>ignoreExtensions</code> defaults to true.
     */
    private OcspStaple getNoncedStaple(CertID certID, X509Certificate cert, Extensions nonce)
    {
        CacheEntry entry = getCurrentEntry(certID);
        if (null != entry && null == entry.staple)
        {
            if (LOG.isLoggable(Level.FINER))
            {
                LOG.finer("Recent OCSP failure recorded; not stapling for certificate: "
                    + cert.getSubjectX500Principal());
            }
            return null;
        }

        synchronized (this)
        {
            if (!pendingNonced.add(certID))
            {
                if (LOG.isLoggable(Level.FINER))
                {
                    LOG.finer("A nonced OCSP fetch is already in flight; not stapling for certificate: "
                        + cert.getSubjectX500Principal());
                }
                return null;
            }
        }

        try
        {
            return accept(cert, fetch(certID, cert, nonce));
        }
        finally
        {
            synchronized (this)
            {
                pendingNonced.remove(certID);
            }
        }
    }

    /**
     * Run at most one fetch per certificate at a time; callers arriving while one is in flight wait
     * for it and take its result from the cache rather than making a second request.
     */
    private OcspStaple fetchSingleFlight(CertID certID, X509Certificate cert)
    {
        Pending inFlight;
        boolean weFetch;

        synchronized (this)
        {
            inFlight = pending.get(certID);
            weFetch = null == inFlight;
            if (weFetch)
            {
                inFlight = new Pending();
                pending.put(certID, inFlight);
            }
        }

        if (!weFetch)
        {
            await(inFlight);

            CacheEntry entry = getCurrentEntry(certID);
            return null == entry ? null : entry.staple;
        }

        OcspStaple staple = null;
        try
        {
            staple = accept(cert, fetch(certID, cert, null));
        }
        finally
        {
            record(certID, staple);

            synchronized (this)
            {
                pending.remove(certID);
            }

            synchronized (inFlight)
            {
                inFlight.done = true;
                inFlight.notifyAll();
            }
        }

        return staple;
    }

    /**
     * Ask the responder, treating any failure as "nothing to staple". A caller is mid-handshake, so
     * neither an unreachable responder nor a fetcher defect may escape into it.
     */
    private OcspStaple fetch(CertID certID, X509Certificate cert, Extensions requestExtensions)
    {
        try
        {
            return fetcher.fetch(certID, cert, requestExtensions);
        }
        catch (IOException e)
        {
            LOG.log(Level.FINE, "Unable to obtain an OCSP response to staple for certificate: "
                + cert.getSubjectX500Principal(), e);
        }
        catch (RuntimeException e)
        {
            LOG.log(Level.WARNING, "Unable to obtain an OCSP response to staple for certificate: "
                + cert.getSubjectX500Principal(), e);
        }

        return null;
    }

    private void await(Pending inFlight)
    {
        long deadline = System.currentTimeMillis() + responseTimeoutMs;

        synchronized (inFlight)
        {
            while (!inFlight.done)
            {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0)
                {
                    LOG.fine("Timed out waiting for an in-flight OCSP fetch");
                    return;
                }

                try
                {
                    inFlight.wait(remaining);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    /**
     * Whether a freshly fetched response is fit to staple. RFC 6960 sec. 4.2.2.1: a response whose
     * thisUpdate is later than our own clock allows is unreliable, and one already past its
     * nextUpdate is stale - in both cases relaying it would only earn the client's rejection.
     */
    private OcspStaple accept(X509Certificate cert, OcspStaple staple)
    {
        if (null == staple)
        {
            return null;
        }

        long now = System.currentTimeMillis();

        Date thisUpdate = staple.getThisUpdate();
        if (null != thisUpdate && thisUpdate.getTime() > (now + MAX_CLOCK_SKEW_MS))
        {
            LOG.warning("Discarding an OCSP response dated " + thisUpdate + " for certificate: "
                + cert.getSubjectX500Principal());
            return null;
        }

        Date nextUpdate = staple.getNextUpdate();
        if (null != nextUpdate && nextUpdate.getTime() <= now)
        {
            LOG.warning("Discarding an OCSP response that expired " + nextUpdate + " for certificate: "
                + cert.getSubjectX500Principal());
            return null;
        }

        return staple;
    }

    private void record(CertID certID, OcspStaple staple)
    {
        if (null == staple)
        {
            // remember the failure briefly, so a dead responder is not retried every handshake
            if (failureLifetimeMs > 0)
            {
                put(certID, new CacheEntry(null, System.currentTimeMillis() + failureLifetimeMs));
            }
            return;
        }

        Date nextUpdate = staple.getNextUpdate();
        if (null == nextUpdate)
        {
            /*
             * RFC 6960 sec. 4.2.2.1: "if nextUpdate is not set, the responder is indicating that
             * newer revocation information is available all the time". Nothing is lost by not
             * holding it - it is still stapled to this handshake, it just costs another request
             * next time.
             */
            LOG.finer("OCSP response states no nextUpdate; stapling it without caching");
            return;
        }

        long expiry = nextUpdate.getTime();
        if (cacheLifetimeMs > 0)
        {
            expiry = Math.min(expiry, System.currentTimeMillis() + cacheLifetimeMs);
        }

        put(certID, new CacheEntry(staple, expiry));
    }

    private synchronized void put(CertID certID, CacheEntry entry)
    {
        cache.put(certID, entry);
    }

    /**
     * @return the entry for certID if it is still within its expiry - which may be a failure entry,
     *         distinguished by a null staple - or null if there is none to use.
     */
    private synchronized CacheEntry getCurrentEntry(CertID certID)
    {
        CacheEntry entry = cache.get(certID);
        if (null == entry)
        {
            return null;
        }

        if (System.currentTimeMillis() >= entry.expiryMs)
        {
            cache.remove(certID);
            return null;
        }

        return entry;
    }

    private CertID createCertID(X509Certificate issuer, BigInteger serialNumber)
    {
        try
        {
            Certificate issuerCert = Certificate.getInstance(issuer.getEncoded());

            MessageDigest digest = helper.createMessageDigest(
                MessageDigestUtils.getDigestName(certIDDigestAlgorithm.getAlgorithm()));

            ASN1OctetString issuerNameHash = new DEROctetString(
                digest.digest(issuerCert.getSubject().getEncoded(ASN1Encoding.DER)));
            ASN1OctetString issuerKeyHash = new DEROctetString(
                digest.digest(issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));

            return new CertID(certIDDigestAlgorithm, issuerNameHash, issuerKeyHash,
                new ASN1Integer(serialNumber));
        }
        catch (Exception e)
        {
            LOG.log(Level.FINE, "Unable to build a CertID for issuer: " + issuer.getSubjectX500Principal(), e);
            return null;
        }
    }

    /**
     * @return the client's <code>id-pkix-ocsp-nonce</code> extension on its own, or null if it asked
     *         for none. Whatever else the client asked for is left behind: see
     *         {@link #getStapledResponse(X509Certificate, X509Certificate, Extensions)}.
     */
    private static Extensions getNonce(Extensions requestExtensions)
    {
        if (null == requestExtensions)
        {
            return null;
        }

        Extension nonce = requestExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        return null == nonce ? null : new Extensions(nonce);
    }

    /**
     * Either a response to staple, or - with a null staple - a note that asking recently did not
     * produce one.
     */
    private static final class CacheEntry
    {
        final OcspStaple staple;
        final long expiryMs;

        CacheEntry(OcspStaple staple, long expiryMs)
        {
            this.staple = staple;
            this.expiryMs = expiryMs;
        }
    }

    private static final class Pending
    {
        boolean done = false;
    }
}
