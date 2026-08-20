package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Caching, freshness, single-flight and failure-suppression rules of {@link OcspStapleCache}, driven
 * through a stub {@link OcspStapleFetcher} so that no test here opens a socket. The HTTP side is
 * {@link OcspStapleHttpFetcher}'s business and is covered by the end-to-end stapling test.
 */
public class OcspStapleCacheTest
    extends TestCase
{
    private static final long SECOND = 1000L;

    private static final int CACHE_SIZE = 4;
    private static final long CACHE_LIFETIME_MS = 3600 * SECOND;
    private static final long FAILURE_LIFETIME_MS = 60 * SECOND;
    private static final long RESPONSE_TIMEOUT_MS = 5 * SECOND;

    private static final JcaJceHelper HELPER = new BCJcaJceHelper();

    private static long serialNumber = 0;

    private X509Certificate caCert;
    private X509Certificate eeCert;
    private X509Certificate otherEECert;

    protected void setUp()
        throws Exception
    {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        X500Name caName = new X500Name("CN=Test CA");
        KeyPair caKeyPair = generateKeyPair();

        caCert = buildCert(caName, caKeyPair.getPrivate(), caName, caKeyPair.getPublic(), true);
        eeCert = buildCert(caName, caKeyPair.getPrivate(), new X500Name("CN=Test EE"),
            generateKeyPair().getPublic(), false);
        otherEECert = buildCert(caName, caKeyPair.getPrivate(), new X500Name("CN=Test EE 2"),
            generateKeyPair().getPublic(), false);
    }

    public void testFetchesOnceThenServesFromCache()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = createCache(fetcher);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));

        assertEquals(1, fetcher.getFetchCount());
    }

    public void testDistinctCertificatesAreCachedSeparately()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = createCache(fetcher);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNotNull(cache.getStapledResponse(otherEECert, caCert, null));
        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNotNull(cache.getStapledResponse(otherEECert, caCert, null));

        assertEquals(2, fetcher.getFetchCount());
    }

    /**
     * RFC 6960 sec. 4.2.2.1: an absent nextUpdate means newer information is available all the time,
     * so the response is still stapled to the handshake it arrived for but is never reused.
     */
    public void testResponseWithoutNextUpdateIsStapledButNotCached()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), null));
        OcspStapleCache cache = createCache(fetcher);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));

        assertEquals(2, fetcher.getFetchCount());
    }

    public void testExpiredCacheEntryIsRefetched()
        throws Exception
    {
        // each response is current when fetched but lapses before the next call
        StubFetcher fetcher = new StubFetcher((OcspStaple)null)
        {
            protected OcspStaple createStaple()
            {
                return staple(hoursFromNow(-1), new Date(System.currentTimeMillis() + 200));
            }
        };
        OcspStapleCache cache = createCache(fetcher);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));

        Thread.sleep(300);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertEquals(2, fetcher.getFetchCount());
    }

    /**
     * The cacheLifetime bound applies even when the responder states a nextUpdate far in the future.
     */
    public void testCacheLifetimeCapsANextUpdateFurtherOut()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, 200L,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, true);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));

        Thread.sleep(300);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertEquals(2, fetcher.getFetchCount());
    }

    /**
     * "Responses whose thisUpdate time is later than the local system time SHOULD be considered
     * unreliable" - RFC 6960 sec. 4.2.2.1. Relaying one would only earn the client's rejection.
     */
    public void testResponseFromTheFutureIsNotStapled()
        throws Exception
    {
        Date thisUpdate = new Date(System.currentTimeMillis() + OcspStapleCache.MAX_CLOCK_SKEW_MS + 60 * SECOND);

        StubFetcher fetcher = new StubFetcher(staple(thisUpdate, hoursFromNow(24)));
        OcspStapleCache cache = createCache(fetcher);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));
    }

    public void testResponseWithinClockSkewIsStapled()
        throws Exception
    {
        Date thisUpdate = new Date(System.currentTimeMillis() + OcspStapleCache.MAX_CLOCK_SKEW_MS - 60 * SECOND);

        StubFetcher fetcher = new StubFetcher(staple(thisUpdate, hoursFromNow(24)));
        OcspStapleCache cache = createCache(fetcher);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
    }

    public void testAlreadyExpiredResponseIsNotStapled()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-48), hoursFromNow(-24)));
        OcspStapleCache cache = createCache(fetcher);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));
    }

    /**
     * An unreachable responder must cost one attempt per failureLifetime, not one per handshake -
     * otherwise a client that keeps connecting keeps the server dialling out.
     */
    public void testFailureIsNotRetriedEveryCall()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(new IOException("responder unreachable"));
        OcspStapleCache cache = createCache(fetcher);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNull(cache.getStapledResponse(eeCert, caCert, null));

        assertEquals(1, fetcher.getFetchCount());
    }

    public void testFailureIsRetriedOnceItsLifetimeElapses()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(new IOException("responder unreachable"));
        OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS,
            200L, RESPONSE_TIMEOUT_MS, true);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));

        Thread.sleep(300);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));
        assertEquals(2, fetcher.getFetchCount());
    }

    /**
     * A fetcher throwing an unchecked exception must not escape into the handshake either.
     */
    public void testRuntimeExceptionFromFetcherIsContained()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(new IllegalStateException("bad response"));
        OcspStapleCache cache = createCache(fetcher);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));
        assertEquals(1, fetcher.getFetchCount());
    }

    public void testNoResponseAvailableIsNotAnError()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher((OcspStaple)null);
        OcspStapleCache cache = createCache(fetcher);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));
        assertEquals(1, fetcher.getFetchCount());
    }

    /**
     * With ignoreExtensions set (the default), a client-supplied nonce does not reach the responder
     * and does not defeat the cache - which is what stops a client forcing an outbound request per
     * handshake.
     */
    public void testNonceIsIgnoredByDefault()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = createCache(fetcher);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, nonceExtensions()));
        assertNotNull(cache.getStapledResponse(eeCert, caCert, nonceExtensions()));

        assertEquals(1, fetcher.getFetchCount());
        assertNull("request extensions should not have been forwarded", fetcher.getLastExtensions());
    }

    /**
     * With ignoreExtensions cleared for JDK parity, the nonce is forwarded and the response - being
     * good for that one request - is neither served from the cache nor put into it.
     */
    public void testNonceBypassesCacheWhenExtensionsHonoured()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, false);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, nonceExtensions()));
        assertNotNull(cache.getStapledResponse(eeCert, caCert, nonceExtensions()));

        assertEquals(2, fetcher.getFetchCount());
        assertNotNull("request extensions should have been forwarded", fetcher.getLastExtensions());

        // and nothing was cached for a subsequent nonce-less caller to pick up
        assertNotNull(cache.getStapledResponse(eeCert, caCert, null));
        assertEquals(3, fetcher.getFetchCount());
    }

    /**
     * Only the nonce is forwarded, never the rest of what a client asked for: a response shaped by
     * one client's extensions would otherwise be cached under the certificate alone and relayed to
     * clients that asked with different ones.
     */
    public void testOnlyTheNonceIsForwarded()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, false);

        assertNotNull(cache.getStapledResponse(eeCert, caCert, noncePlusOtherExtensions()));

        Extensions forwarded = fetcher.getLastExtensions();
        assertNotNull("the nonce should have been forwarded", forwarded);
        assertNotNull(forwarded.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertNull("nothing but the nonce should have been forwarded",
            forwarded.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_response));
    }

    /**
     * A nonced request the responder refuses says nothing about the shared, extension-free request
     * every other client uses - so it must not be recorded as a failure. Recording it would let one
     * client's nonce cost every other client its staple for a failureLifetime, re-armable by
     * reconnecting.
     */
    public void testNoncedFailureDoesNotSuppressOtherCallers()
        throws Exception
    {
        NoncedFailureStubFetcher fetcher = new NoncedFailureStubFetcher(
            staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, false);

        assertNull(cache.getStapledResponse(eeCert, caCert, nonceExtensions()));

        assertNotNull("a nonced failure should not suppress the shared request",
            cache.getStapledResponse(eeCert, caCert, null));

        assertEquals(2, fetcher.getFetchCount());
    }

    /**
     * The nonced path reads the failure entry even though it never writes one: a responder that has
     * just failed the shared request is not worth dialling again on a client's behalf.
     */
    public void testNoncedCallerRespectsARecordedFailure()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(new IOException("responder unreachable"));
        OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, false);

        assertNull(cache.getStapledResponse(eeCert, caCert, null));
        assertNull(cache.getStapledResponse(eeCert, caCert, nonceExtensions()));

        assertEquals("the recorded failure should have spared the responder a second call", 1,
            fetcher.getFetchCount());
    }

    /**
     * A nonced response cannot be shared, so concurrent nonced handshakes cannot be single-flighted
     * into one - but they must not become one outbound request each either. At most one nonced fetch
     * per certificate is in flight; the rest go unstapled.
     */
    public void testConcurrentNoncedCallersMakeOneRequest()
        throws Exception
    {
        final int threadCount = 4;

        BlockingStubFetcher fetcher = new BlockingStubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        final OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, false);

        final List<Object> results = new ArrayList<Object>();
        Thread[] threads = new Thread[threadCount];

        for (int i = 0; i < threadCount; ++i)
        {
            threads[i] = new Thread(new Runnable()
            {
                public void run()
                {
                    OCSPResponse response = cache.getStapledResponse(eeCert, caCert, nonceExtensions());
                    synchronized (results)
                    {
                        results.add(response);
                    }
                }
            });
        }

        for (int i = 0; i < threadCount; ++i)
        {
            threads[i].start();
        }

        // one gets in and blocks; give the others time to be turned away, then let it finish
        fetcher.awaitCallers(1);
        Thread.sleep(200);
        fetcher.release();

        for (int i = 0; i < threadCount; ++i)
        {
            threads[i].join(30 * SECOND);
            assertFalse("caller thread did not complete", threads[i].isAlive());
        }

        assertEquals("a nonce per handshake must not become a request per handshake", 1,
            fetcher.getFetchCount());

        int stapled = 0;
        for (int i = 0; i != results.size(); ++i)
        {
            if (null != results.get(i))
            {
                ++stapled;
            }
        }

        assertEquals(threadCount, results.size());
        assertEquals("exactly the caller that fetched should have been stapled", 1, stapled);
    }

    /**
     * A nonced fetch is nobody else's, so an ordinary caller arriving while one is in flight must go
     * and get its own response rather than wait out the timeout for one it can never be given.
     */
    public void testCacheableCallerDoesNotWaitBehindANoncedFetch()
        throws Exception
    {
        BlockingStubFetcher fetcher = new BlockingStubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)),
            true);
        final OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, false);

        Thread nonced = new Thread(new Runnable()
        {
            public void run()
            {
                cache.getStapledResponse(eeCert, caCert, nonceExtensions());
            }
        });
        nonced.start();

        try
        {
            fetcher.awaitCallers(1);

            long started = System.currentTimeMillis();

            assertNotNull("an ordinary caller should not be starved by a nonced fetch",
                cache.getStapledResponse(eeCert, caCert, null));

            long elapsed = System.currentTimeMillis() - started;
            assertTrue("an ordinary caller waited on the nonced fetch (" + elapsed + "ms)",
                elapsed < RESPONSE_TIMEOUT_MS);
        }
        finally
        {
            fetcher.release();
        }

        nonced.join(30 * SECOND);
        assertFalse("nonced caller thread did not complete", nonced.isAlive());

        assertEquals(2, fetcher.getFetchCount());
    }

    public void testCacheIsBoundedBySize()
        throws Exception
    {
        StubFetcher fetcher = new StubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        OcspStapleCache cache = new OcspStapleCache(HELPER, fetcher, 1, CACHE_LIFETIME_MS,
            FAILURE_LIFETIME_MS, RESPONSE_TIMEOUT_MS, true);

        cache.getStapledResponse(eeCert, caCert, null);
        cache.getStapledResponse(otherEECert, caCert, null);

        // the first entry was evicted by the second, so asking again costs another fetch
        cache.getStapledResponse(eeCert, caCert, null);

        assertEquals(3, fetcher.getFetchCount());
    }

    /**
     * Concurrent handshakes for the same certificate must produce one outbound request, not one
     * each. A weakly-referenced or unsynchronized cache passes the sequential tests above and fails
     * this one.
     */
    public void testConcurrentCallersShareOneFetch()
        throws Exception
    {
        final int threadCount = 8;

        BlockingStubFetcher fetcher = new BlockingStubFetcher(staple(hoursFromNow(-1), hoursFromNow(24)));
        final OcspStapleCache cache = createCache(fetcher);

        final List<Object> results = new ArrayList<Object>();
        Thread[] threads = new Thread[threadCount];

        for (int i = 0; i < threadCount; ++i)
        {
            threads[i] = new Thread(new Runnable()
            {
                public void run()
                {
                    OCSPResponse response = cache.getStapledResponse(eeCert, caCert, null);
                    synchronized (results)
                    {
                        results.add(response);
                    }
                }
            });
        }

        for (int i = 0; i < threadCount; ++i)
        {
            threads[i].start();
        }

        // let them all arrive and queue up behind the one fetch, then release it
        fetcher.awaitCallers(1);
        Thread.sleep(200);
        fetcher.release();

        for (int i = 0; i < threadCount; ++i)
        {
            threads[i].join(30 * SECOND);
            assertFalse("caller thread did not complete", threads[i].isAlive());
        }

        assertEquals(1, fetcher.getFetchCount());
        assertEquals(threadCount, results.size());

        for (int i = 0; i != results.size(); ++i)
        {
            assertNotNull("every concurrent caller should get the response", results.get(i));
        }
    }

    private OcspStapleCache createCache(OcspStapleFetcher fetcher)
    {
        return new OcspStapleCache(HELPER, fetcher, CACHE_SIZE, CACHE_LIFETIME_MS, FAILURE_LIFETIME_MS,
            RESPONSE_TIMEOUT_MS, true);
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    private static X509Certificate buildCert(X500Name issuer, PrivateKey issuerKey, X500Name subject,
        java.security.PublicKey subjectKey, boolean ca)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer,
            BigInteger.valueOf(++serialNumber), new Date(now - 5000), new Date(now + 30 * 60 * 1000),
            subject, SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded()));

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);

        return new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static Date hoursFromNow(int hours)
    {
        return new Date(System.currentTimeMillis() + (hours * 3600L * SECOND));
    }

    private static OcspStaple staple(Date thisUpdate, Date nextUpdate)
    {
        /*
         * The cache never looks inside the response - it is the client that validates what a server
         * relays - so a successful shell with no responseBytes is enough to assert identity on.
         */
        OCSPResponse response = new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL), null);

        return new OcspStaple(response, thisUpdate, nextUpdate);
    }

    private static Extensions nonceExtensions()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
            new DEROctetString(new byte[16])));

        return Extensions.getInstance(new DERSequence(v));
    }

    /**
     * A nonce alongside an extension that is not the nonce - here the acceptable-response-types of
     * RFC 6960 sec. 4.4.3 - so a test can assert which of the two is passed on.
     */
    private static Extensions noncePlusOtherExtensions()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
            new DEROctetString(new byte[16])));
        v.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_response, false,
            new DEROctetString(new DERSequence(OCSPObjectIdentifiers.id_pkix_ocsp_basic).getEncoded())));

        return Extensions.getInstance(new DERSequence(v));
    }

    private static class StubFetcher
        implements OcspStapleFetcher
    {
        private final OcspStaple staple;
        private final IOException ioException;
        private final RuntimeException runtimeException;

        private int fetchCount = 0;
        private Extensions lastExtensions;

        StubFetcher(OcspStaple staple)
        {
            this(staple, null, null);
        }

        StubFetcher(IOException ioException)
        {
            this(null, ioException, null);
        }

        StubFetcher(RuntimeException runtimeException)
        {
            this(null, null, runtimeException);
        }

        private StubFetcher(OcspStaple staple, IOException ioException, RuntimeException runtimeException)
        {
            this.staple = staple;
            this.ioException = ioException;
            this.runtimeException = runtimeException;
        }

        public OcspStaple fetch(CertID certID, X509Certificate cert, Extensions requestExtensions)
            throws IOException
        {
            synchronized (this)
            {
                ++fetchCount;
                lastExtensions = requestExtensions;
            }

            onFetch(requestExtensions);

            if (null != ioException)
            {
                throw ioException;
            }
            if (null != runtimeException)
            {
                throw runtimeException;
            }

            return createStaple();
        }

        /**
         * Overridden where a test needs each fetch to yield a fresh response rather than the same
         * object again - e.g. when the response's own validity is short enough to lapse between
         * calls.
         */
        protected OcspStaple createStaple()
        {
            return staple;
        }

        /**
         * Overridden where a test needs the fetch to block or fail, and to do so for some requests
         * only - which is what the extensions are handed over for.
         */
        protected void onFetch(Extensions requestExtensions)
            throws IOException
        {
        }

        synchronized int getFetchCount()
        {
            return fetchCount;
        }

        synchronized Extensions getLastExtensions()
        {
            return lastExtensions;
        }
    }

    /**
     * A responder that refuses whatever a client asked to have forwarded, but answers the shared
     * request - as one rejecting a nonce it does not support would.
     */
    private static class NoncedFailureStubFetcher
        extends StubFetcher
    {
        NoncedFailureStubFetcher(OcspStaple staple)
        {
            super(staple);
        }

        protected void onFetch(Extensions requestExtensions)
            throws IOException
        {
            if (null != requestExtensions)
            {
                throw new IOException("responder rejected the nonced request");
            }
        }
    }

    /**
     * Holds its caller inside fetch() until released, so the single-flight behaviour of concurrent
     * callers can be observed rather than raced for.
     */
    private static class BlockingStubFetcher
        extends StubFetcher
    {
        private final Object lock = new Object();
        private final boolean noncedOnly;

        private int callers = 0;
        private boolean released = false;

        BlockingStubFetcher(OcspStaple staple)
        {
            this(staple, false);
        }

        /**
         * @param noncedOnly hold only the fetches carrying request extensions, letting the ordinary
         *                   ones through - so a test can have a nonced fetch in flight and watch
         *                   what an ordinary caller arriving behind it does.
         */
        BlockingStubFetcher(OcspStaple staple, boolean noncedOnly)
        {
            super(staple);

            this.noncedOnly = noncedOnly;
        }

        protected void onFetch(Extensions requestExtensions)
        {
            if (noncedOnly && null == requestExtensions)
            {
                return;
            }

            synchronized (lock)
            {
                ++callers;
                lock.notifyAll();

                while (!released)
                {
                    try
                    {
                        lock.wait(30 * SECOND);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }

        void awaitCallers(int count)
            throws InterruptedException
        {
            synchronized (lock)
            {
                while (callers < count)
                {
                    lock.wait(30 * SECOND);
                }
            }
        }

        void release()
        {
            synchronized (lock)
            {
                released = true;
                lock.notifyAll();
            }
        }
    }
}
