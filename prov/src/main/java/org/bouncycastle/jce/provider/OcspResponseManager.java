package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.io.Streams;

public class OcspResponseManager
{
    private static final Logger LOG = Logger.getLogger(OcspResponseManager.class.getName());

    private static final int DEFAULT_CONNECT_TIMEOUT = 15000; // milliseconds
    private static final int DEFAULT_READ_TIMEOUT = 15000; // milliseconds
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 32 * 1024;

    private static final int DEFAULT_CACHE_SIZE = 256;
    private static final int DEFAULT_CACHE_LIFETIME = 3600; // seconds

    // Revocation check OCSP parameters.
    private static boolean ocspEnable = !Properties.isOverrideSetTo("ocsp.enable", false); // OCSP validation enabled by default unless explicit override
    private static String ocspURL = Properties.getPropertyValue("ocsp.responderURL");
    private static int ocspTimeout = Properties.asInteger("com.sun.security.ocsp.timeout", DEFAULT_CONNECT_TIMEOUT);
    private static int ocspReadTimeout = Properties.asInteger("com.sun.security.ocsp.readtimeout", DEFAULT_READ_TIMEOUT);

    // Server OCSP stapling parameters.
    private static boolean responderOverride = Properties.isOverrideSet("jdk.tls.stapling.responderOverride");
    private static String responderUri = Properties.getPropertyValue("jdk.tls.stapling.responderURI");
    private static int responseTimeout = Properties.asInteger("jdk.tls.stapling.responseTimeout", DEFAULT_READ_TIMEOUT);
    private static boolean ignoreExtensions = Properties.isOverrideSet("jdk.tls.stapling.ignoreExtensions");

    // Caching parameters.
    private static int cacheSize = Properties.asInteger("jdk.tls.stapling.cacheSize", DEFAULT_CACHE_SIZE);
    private static int cacheLifetime = Properties.asInteger("jdk.tls.stapling.cacheLifetime", DEFAULT_CACHE_LIFETIME);

    // OCSP response cache.
    private static final Map<CertID, CachedOCSPResponse> cache = Collections.synchronizedMap(new WeakHashMap<CertID, CachedOCSPResponse>());

    /**
     * Convenience method to reset all the parameters.
     */
    public static void reset()
    {
        ocspEnable = !Properties.isOverrideSetTo("ocsp.enable", false);
        ocspURL = Properties.getPropertyValue("ocsp.responderURL");
        ocspTimeout = Properties.asInteger("com.sun.security.ocsp.timeout", DEFAULT_CONNECT_TIMEOUT);
        ocspReadTimeout = Properties.asInteger("com.sun.security.ocsp.readtimeout", DEFAULT_READ_TIMEOUT);

        responderOverride = Properties.isOverrideSet("jdk.tls.stapling.responderOverride");
        responderUri = Properties.getPropertyValue("jdk.tls.stapling.responderURI");
        responseTimeout = Properties.asInteger("jdk.tls.stapling.responseTimeout", DEFAULT_READ_TIMEOUT);
        ignoreExtensions = Properties.isOverrideSet("jdk.tls.stapling.ignoreExtensions");

        cacheSize = Properties.asInteger("jdk.tls.stapling.cacheSize", DEFAULT_CACHE_SIZE);
        cacheLifetime = Properties.asInteger("jdk.tls.stapling.cacheLifetime", DEFAULT_CACHE_LIFETIME);

        cache.clear();
    }

    public static OCSPResponse getOCSPResponseForRevocationCheck(X509Certificate cert, X509Certificate issuer, List<Extension> extensionList, URI parentOcspURI, JcaJceHelper helper) throws CertPathValidatorException
    {
        // check OCSP revocation checking is disabled
        if (!ocspEnable)
        {
            LOG.warning("[revocation check] OCSP disabled by \"ocsp.enable\" setting");
            throw new RecoverableCertPathValidatorException("[revocation check] OCSP disabled by \"ocsp.enable\" setting", null, null, -1);
        }

        LOG.info("[revocation check] Getting OCSP response for cert: " + cert.getSubjectX500Principal());

        // create valid CertID
        CertID certID = createCertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), issuer, new ASN1Integer(cert.getSerialNumber()), helper);
        if (certID == null)
        {
            throw new CertPathValidatorException("[revocation check] Error creating CertID for certificate: " + cert.getSubjectX500Principal(), null, null, -1);
        }

        // handle ocsp_no_check extension of the cert
        if (cert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null)
        {
            LOG.info("[revocation check] Found ocsp_no_check extension. Skipping OCSP retrieval for cert: " + cert.getSubjectX500Principal());
            return null;
        }

        // validate responder URL
        URL responderURL = getResponderURLForRevocationCheck(cert, parentOcspURI);

        // build extensions
        Extensions extensions = buildExtensions(extensionList);

        // at this point we have a valid responder, so we need to make an HTTP request
        LOG.info("[revocation check] Sending POST request to: " + responderURL);
        try
        {
            byte[] request = buildRequest(certID, extensions);

            // make HTTP call
            OCSPResponse response = sendPostRequest(responderURL, request, ocspTimeout, ocspReadTimeout);
            if (OCSPResponseStatus.SUCCESSFUL == response.getResponseStatus().getIntValue())
            {
                LOG.info("[revocation check] Successfully retrieved OCSP response for cert: " + cert.getSubjectX500Principal());
                return response;
            }
        }
        catch (IOException e)
        {
            LOG.warning("[revocation check] Network error while trying to retrieve OCSP response for cert: " + cert.getSubjectX500Principal() + " from responder URL: " + responderURL);
            throw new RecoverableCertPathValidatorException("[revocation check] Network error while trying to retrieve OCSP response for cert: " + cert.getSubjectX500Principal() + " from responder URL: " + responderURL, e, null, -1);
        }
        return null;
    }

    public static OCSPResponse getOCSPResponseForStapling(X509Certificate cert, X509Certificate issuerX509, Extensions extensions, JcaJceHelper helper)
    {
        LOG.info("[stapling] Getting OCSP response for cert: " + cert.getSubjectX500Principal());

        // create CertID
        CertID certID = createCertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), issuerX509, new ASN1Integer(cert.getSerialNumber()), helper);
        if (certID == null)
        {
            // if we were unable to build a CertID then there is no point on going forward
            LOG.warning("[stapling] Unable to build a CertID for cert: " + cert.getSubjectX500Principal());
            return null;
        }

        CachedOCSPResponse cachedResponse = getCachedOCSPResponse(certID, extensions);
        if (cachedResponse != null)
        {
            LOG.info("[stapling] Found cached OCSP response for cert: " + cert.getSubjectX500Principal());
            return cachedResponse.response;
        }

        // handle ocsp_no_check extension
        if (cert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null)
        {
            LOG.info("[stapling] Found ocsp_no_check extension. Skipping OCSP retrieval for cert: " + cert.getSubjectX500Principal());
            return null;
        }

        // if not found retrieve it via http
        URL responderUrl = getResponderURLForServer(cert);
        if (responderUrl == null)
        {
            // if we could not retrieve a valid responder URL then return a null response
            LOG.warning("[stapling] Unable to find a valid responder URL for cert: " + cert.getSubjectX500Principal());
            return null;
        }

        LOG.info("[stapling] Sending POST request to: " + responderUrl);
        try
        {
            // build the OCSP request
            byte[] request = buildRequest(certID, ignoreExtensions ? null : extensions);

            // make HTTP call
            OCSPResponse response = sendPostRequest(responderUrl, request, responseTimeout, responseTimeout);
            if (OCSPResponseStatus.SUCCESSFUL == response.getResponseStatus().getIntValue())
            {
                LOG.info("[stapling] Successfully retrieved OCSP response for cert: " + cert.getSubjectX500Principal());
                cacheOCSPResponse(certID, response);
                return response;
            }
        }
        catch (IOException e)
        {
            LOG.warning("[stapling] Network error while trying to retrieve OCSP response for cert: " + cert.getSubjectX500Principal() + " from responder URL: " + responderUrl);
        }
        return null;
    }

    private static URL getResponderURLForRevocationCheck(X509Certificate cert, URI parentOcspURI) throws CertPathValidatorException
    {
        LOG.info("[revocation check] Getting OCSP responder URL for cert: " + cert.getSubjectX500Principal());
        // try to get parent responder URL
        URL responderURL = null;
        if (parentOcspURI != null)
        {
            try
            {
                responderURL = parentOcspURI.toURL();
                LOG.info("[revocation check] Found OCSP responder URL from parent PKIXRevocationChecker: " + responderURL);
            }
            catch (Exception e)
            {
                // invalid responder URL - fallback to configured responder
            }
        }
        // if not found try to get configured responder URL
        if (responderURL == null && ocspURL != null && !ocspURL.isEmpty())
        {
            try
            {
                responderURL = URI.create(ocspURL).toURL();
                LOG.info("[revocation check] Found OCSP responder URL from property ocsp.responderURL: " + responderURL);
            }
            catch (Exception e)
            {
                // misconfigured ocsp.responderURL
                throw new CertPathValidatorException("[revocation check] Misconfigured property ocsp.responderURL: " + ocspURL, e);
            }
        }
        // if still not found try to get the responder URL from the AIA extension of the cert
        if (responderURL == null)
        {
            responderURL = getResponderURLFromCert(cert);
            if (responderURL != null)
            {
                LOG.info("[revocation check] Found OCSP responder URL from cert AIA extension: " + responderURL);
            }
        }
        // if still not found at this point then block the request
        if (responderURL == null)
        {
            LOG.warning("[revocation check] Unable to find a valid OCSP responder URL for cert: " + cert.getSubjectX500Principal());
            throw new RecoverableCertPathValidatorException("[revocation check] Unable to find a valid OCSP responder URL for cert: " + cert.getSubjectX500Principal(), null, null, -1);
        }
        return responderURL;
    }

    private static URL getResponderURLForServer(X509Certificate cert)
    {
        LOG.info("[stapling] Getting OCSP responder URL for cert: " + cert.getSubjectX500Principal());

        URL responderUrl = null;
        if (responderOverride && responderUri != null && !responderUri.isEmpty())
        {
            try
            {
                responderUrl = URI.create(responderUri).toURL();
                LOG.info("[stapling] Found OCSP responder URL from property jdk.tls.stapling.responderURI: " + responderUrl);
            }
            catch (Exception e)
            {
                // invalid responder URL - fallback to cert responder
            }
        }
        // if not found try to get the responder URL from the AIA extension of the cert
        if (responderUrl == null)
        {
            responderUrl = getResponderURLFromCert(cert);
            if (responderUrl != null)
            {
                LOG.info("[stapling] Found OCSP responder URL from cert AIA extension: " + responderUrl);
            }
        }
        return responderUrl;
    }

    private static URL getResponderURLFromCert(X509Certificate cert)
    {
        byte[] extValue = cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.getId());
        if (extValue != null)
        {
            AuthorityInformationAccess aiAccess = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(extValue).getOctets());
            AccessDescription[] descriptions = aiAccess.getAccessDescriptions();
            for (int i = 0; i != descriptions.length; i++)
            {
                AccessDescription aDesc = descriptions[i];
                if (AccessDescription.id_ad_ocsp.equals(aDesc.getAccessMethod()))
                {
                    GeneralName name = aDesc.getAccessLocation();
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
                    {
                        try
                        {
                            return URI.create(((ASN1String) name.getName()).getString()).toURL();
                        }
                        catch (Exception e)
                        {
                            // ignore...
                        }
                    }
                }
            }
        }
        return null;
    }

    private static CertID createCertID(AlgorithmIdentifier digestAlg, X509Certificate issuerX509, ASN1Integer serialNumber, JcaJceHelper helper)
    {
        try
        {
            Certificate issuerCert = Certificate.getInstance(issuerX509.getEncoded());
            MessageDigest digest = helper.createMessageDigest(MessageDigestUtils.getDigestName(digestAlg.getAlgorithm()));
            ASN1OctetString issuerNameHash = new DEROctetString(digest.digest(issuerCert.getSubject().getEncoded(ASN1Encoding.DER)));
            ASN1OctetString issuerKeyHash = new DEROctetString(digest.digest(issuerCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
            return new CertID(digestAlg, issuerNameHash, issuerKeyHash, serialNumber);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static byte[] buildRequest(CertID certID, Extensions extensions) throws IOException
    {
        ASN1EncodableVector requests = new ASN1EncodableVector();
        requests.add(new Request(certID, null));

        // build request
        TBSRequest tbsReq = new TBSRequest(null, new DERSequence(requests), extensions);

        // JSSE doesn't provide a signature when sending the request
        return new OCSPRequest(tbsReq, null).getEncoded();
    }

    private static Extensions buildExtensions(List<Extension> extensionList)
    {
        // build extensions
        ASN1EncodableVector extVector = new ASN1EncodableVector();
        for (int i = 0; i < extensionList.size(); i++)
        {
            Extension extension = extensionList.get(i);
            extVector.add(new org.bouncycastle.asn1.x509.Extension(new ASN1ObjectIdentifier(extension.getId()), extension.isCritical(), extension.getValue()));
        }
        return extVector.size() > 0 ? Extensions.getInstance(new DERSequence(extVector)) : null;
    }

    private static OCSPResponse sendPostRequest(URL ocspUrl, byte[] ocspRequest, int connectTimeout, int readTimeout) throws IOException
    {
        HttpURLConnection ocspCon = null;
        try
        {
            ocspCon = (HttpURLConnection) ocspUrl.openConnection();
            ocspCon.setConnectTimeout(connectTimeout);
            ocspCon.setReadTimeout(readTimeout);
            ocspCon.setDoOutput(true);
            ocspCon.setDoInput(true);
            ocspCon.setRequestMethod("POST");
            ocspCon.setRequestProperty("Content-type", "application/ocsp-request");
            ocspCon.setRequestProperty("Content-length", String.valueOf(ocspRequest.length));

            OutputStream reqOut = ocspCon.getOutputStream();
            reqOut.write(ocspRequest);
            reqOut.flush();

            InputStream reqIn = ocspCon.getInputStream();
            int contentLength = ocspCon.getContentLength();
            if (contentLength < 0)
            {
                contentLength = DEFAULT_MAX_RESPONSE_SIZE;
            }
            return OCSPResponse.getInstance(Streams.readAllLimited(reqIn, contentLength));
        }
        finally
        {
            if (ocspCon != null)
            {
                ocspCon.disconnect();
            }
        }
    }

    private static CachedOCSPResponse getCachedOCSPResponse(CertID certID, Extensions extensions)
    {
        // if nonce extension is present in the request extensions don't retrieve from cache
        if (extensions != null && extensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce) != null)
        {
            LOG.fine("Nonce found in the request, skipping OCSP response cache check");
            return null;
        }
        CachedOCSPResponse cachedResponse = cache.get(certID);
        if (cachedResponse != null)
        {
            if (!isResponseExpired(cachedResponse))
            {
                return cachedResponse;
            }
            else
            {
                LOG.fine("Expired cached OCSP response");
            }
        }
        return null;
    }

    private static void cacheOCSPResponse(CertID certID, OCSPResponse response)
    {
        // check cache is enabled
        if (cacheLifetime > 0 && cacheSize > 0)
        {
            // first clean expired entries from the cache
            cleanCache();

            // cache only if the cache is not full
            if (cache.size() < cacheSize)
            {
                Date nextUpdate = getNextUpdateFromResponse(response, certID);

                // add the OCSP response to the cache with the current timestamp
                cache.put(certID, new CachedOCSPResponse(response, System.currentTimeMillis(), nextUpdate));
                LOG.fine("Cached OCSP response for CertID: " + certID.getSerialNumber());
            }
        }
    }

    private static void cleanCache()
    {
        int cleanedEntries = 0;
        Iterator<Map.Entry<CertID, CachedOCSPResponse>> iterator = cache.entrySet().iterator();
        while (iterator.hasNext())
        {
            Map.Entry<CertID, CachedOCSPResponse> entry = iterator.next();
            if (isResponseExpired(entry.getValue()))
            {
                iterator.remove();
                cleanedEntries++;
            }
        }
        if (cleanedEntries > 0)
        {
            LOG.fine("Cleaned expired cache entries: " + cleanedEntries);
        }
    }

    private static boolean isResponseExpired(CachedOCSPResponse cachedResponse)
    {
        boolean exceededLifetime = (System.currentTimeMillis() - cachedResponse.timestamp) > cacheLifetime * 1000L; // cache lifetime is in seconds
        boolean exceededNextUpdate = cachedResponse.nextUpdate != null && cachedResponse.nextUpdate.before(new Date());
        return exceededLifetime || exceededNextUpdate;
    }

    private static Date getNextUpdateFromResponse(OCSPResponse response, CertID certID)
    {
        // try to find the nextUpdate extension on the response
        Date nextUpdate = null;

        BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(ASN1OctetString.getInstance(response.getResponseBytes().getResponse()).getOctets());
        if (basicResp != null)
        {
            ResponseData responseData = ResponseData.getInstance(basicResp.getTbsResponseData());
            if (responseData != null)
            {
                ASN1Sequence responses = responseData.getResponses();

                for (int i = 0; i < responses.size(); i++)
                {
                    SingleResponse resp = SingleResponse.getInstance(responses.getObjectAt(i));
                    if (resp != null)
                    {
                        if (certID.equals(resp.getCertID()))
                        {
                            ASN1GeneralizedTime nextUp = resp.getNextUpdate();
                            if (nextUp != null)
                            {
                                try
                                {
                                    nextUpdate = nextUp.getDate();
                                    LOG.fine("Found nextUpdate field on response: " + nextUpdate);
                                }
                                catch (ParseException e)
                                {
                                    // should not happen
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
        return nextUpdate;
    }

    private static final class CachedOCSPResponse
    {
        final OCSPResponse response;
        final long timestamp;
        final Date nextUpdate;

        CachedOCSPResponse(OCSPResponse response, long timestamp, Date nextUpdate)
        {
            this.response = response;
            this.timestamp = timestamp;
            this.nextUpdate = nextUpdate;
        }
    }

}
