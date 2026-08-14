package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.io.StreamOverflowException;
import org.bouncycastle.util.io.Streams;

class OcspCache
{
    private static final int DEFAULT_TIMEOUT = 15000;
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024;

    /**
     * Tolerance between our clock and the responder's when judging whether a response is dated in
     * the future. 15 minutes, matching what the JDK's own OCSP client allows.
     */
    static final long MAX_CLOCK_SKEW_MS = 15 * 60 * 1000L;

    private static Map<URI, WeakReference<Map<CertID, OCSPResponse>>> cache
        = Collections.synchronizedMap(new WeakHashMap<URI, WeakReference<Map<CertID, OCSPResponse>>>());

    static synchronized OCSPResponse getOcspResponse(
        CertID certID, PKIXCertRevocationCheckerParameters parameters,
        URI ocspResponder, X509Certificate responderCert, List<Extension> ocspExtensions,
        JcaJceHelper helper)
        throws CertPathValidatorException
    {
        Map<CertID, OCSPResponse> responseMap = null;

        WeakReference<Map<CertID, OCSPResponse>> markerRef = cache.get(ocspResponder);
        if (markerRef != null)
        {
            responseMap = markerRef.get();
        }

        if (responseMap != null)
        {
            OCSPResponse response = responseMap.get(certID);
            if (response != null)
            {
                BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(
                    ASN1OctetString.getInstance(response.getResponseBytes().getResponse()).getOctets());

                boolean matchFound = isCertIDFoundAndReusable(basicResp, parameters.getValidDate(), certID);
                if (matchFound)
                {
                    return response;
                }
                else
                {
                    responseMap.remove(certID);
                }
            }
        }

        URL ocspUrl;
        try
        {
            ocspUrl = ocspResponder.toURL();
        }
        catch (MalformedURLException e)
        {
            throw new CertPathValidatorException("configuration error: " + e.getMessage(),
                e, parameters.getCertPath(), parameters.getIndex());
        }

        //
        // basic request generation
        //
        ASN1EncodableVector requests = new ASN1EncodableVector();

        requests.add(new Request(certID, null));

        List exts = ocspExtensions;
        ASN1EncodableVector requestExtensions = new ASN1EncodableVector();

        byte[] nonce = null;
        for (int i = 0; i != exts.size(); i++)
        {
            Extension ext = (Extension)exts.get(i);

            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(ext.getId());
            ASN1OctetString value = new DEROctetString(ext.getValue());

            if (OCSPObjectIdentifiers.id_pkix_ocsp_nonce.equals(oid))
            {
                nonce = Arrays.clone(value.getOctets());
            }

            requestExtensions.add(new org.bouncycastle.asn1.x509.Extension(oid, ext.isCritical(), value));
        }

        // TODO: configure originator
        TBSRequest tbsReq;
        if (requestExtensions.size() != 0)
        {
            tbsReq = new TBSRequest(null, new DERSequence(requests),
                Extensions.getInstance(new DERSequence(requestExtensions)));
        }
        else
        {
            tbsReq = new TBSRequest(null, new DERSequence(requests), (Extensions)null);
        }

        org.bouncycastle.asn1.ocsp.Signature signature = null;

        try
        {

            byte[] request = new OCSPRequest(tbsReq, signature).getEncoded();

            HttpURLConnection ocspCon = (HttpURLConnection)ocspUrl.openConnection();
            ocspCon.setConnectTimeout(DEFAULT_TIMEOUT);
            ocspCon.setReadTimeout(DEFAULT_TIMEOUT);
            ocspCon.setDoOutput(true);
            ocspCon.setDoInput(true);
            ocspCon.setRequestMethod("POST");
            ocspCon.setRequestProperty("Content-type", "application/ocsp-request");
            ocspCon.setRequestProperty("Content-length", String.valueOf(request.length));

            OutputStream reqOut = ocspCon.getOutputStream();
            reqOut.write(request);
            reqOut.flush();

            InputStream reqIn = ocspCon.getInputStream();

            OCSPResponse response = OCSPResponse.getInstance(
                readResponse(reqIn, getResponseSizeLimit(ocspCon.getContentLength())));

            if (OCSPResponseStatus.SUCCESSFUL == response.getResponseStatus().getIntValue())
            {
                boolean validated = false;
                ResponseBytes respBytes = ResponseBytes.getInstance(response.getResponseBytes());

                if (respBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic))
                {
                    BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(respBytes.getResponse().getOctets());

                    validated = ProvOcspRevocationChecker.validatedOcspResponse(basicResp, parameters, nonce, responderCert, helper)
                                && isCertIDFoundAndCurrent(basicResp, parameters.getValidDate(), certID);
                }

                if (!validated)
                {
                    throw new CertPathValidatorException(
                        "OCSP response failed to validate", null, parameters.getCertPath(), parameters.getIndex());
                }

                markerRef = cache.get(ocspResponder);
                if (markerRef != null)
                {
                    responseMap = markerRef.get();
                }

                if (responseMap != null)
                {
                    responseMap.put(certID, response);
                }
                else
                {
                    responseMap = new HashMap<CertID, OCSPResponse>();
                    responseMap.put(certID, response);
                    cache.put(ocspResponder, new WeakReference<Map<CertID, OCSPResponse>>(responseMap));
                }

                return response;
            }
            else
            {
                throw new CertPathValidatorException(
                    "OCSP responder failed: " + response.getResponseStatus().getValue(),
                    null, parameters.getCertPath(), parameters.getIndex());
            }
        }
        catch (IOException e)
        {
            // an unreachable or failing responder must surface as recoverable so
            // ProvRevocationChecker can fall back to CRL-based checking.
            throw new RecoverableCertPathValidatorException("unable to get OCSP response from " + ocspUrl + ": " + e.getMessage(),
                     e, parameters.getCertPath(), parameters.getIndex());
        }
    }

    /**
     * Read the response, up to responseSizeLimit bytes. Streams.readAllLimited reports an
     * over-long stream as a bare "Data Overflow", which says nothing about what was being read or
     * what to change, so it is restated here in terms of the limit and the property that sets it.
     * The type stays an IOException, so the caller still treats this the way it treats an
     * unreachable responder - recoverable, falling back to CRL checking.
     */
    static byte[] readResponse(InputStream reqIn, int responseSizeLimit)
        throws IOException
    {
        try
        {
            return Streams.readAllLimited(reqIn, responseSizeLimit);
        }
        catch (StreamOverflowException e)
        {
            throw new StreamOverflowException("OCSP response exceeds " + responseSizeLimit
                + " bytes (see " + Properties.OCSP_MAX_RESPONSE_SIZE + ")");
        }
    }

    /**
     * How many bytes we are prepared to read for an OCSP response: the responder's declared
     * Content-Length where it has given one and it is no larger than our own ceiling, that ceiling
     * otherwise. A real response is a few KB and the declared length is the responder's to choose,
     * so it may narrow the read but never widen it - a responder that declares and streams
     * hundreds of megabytes is cut off instead of being read into the heap. The ceiling is
     * {@link Properties#OCSP_MAX_RESPONSE_SIZE}, defaulting to 64K.
     */
    static int getResponseSizeLimit(int contentLength)
    {
        int maxResponseSize = Properties.asInteger(Properties.OCSP_MAX_RESPONSE_SIZE, DEFAULT_MAX_RESPONSE_SIZE);

        // a configured value that cannot be a size is no reason to read without a limit
        if (maxResponseSize <= 0)
        {
            maxResponseSize = DEFAULT_MAX_RESPONSE_SIZE;
        }

        if (contentLength < 0 || contentLength > maxResponseSize)
        {
            return maxResponseSize;
        }

        return contentLength;
    }

    /**
     * Whether the response answers for certID and is usable at validDate. Applied to a response as
     * it arrives from the responder, so a missing nextUpdate is no objection - the responder is
     * entitled not to state one.
     */
    static boolean isCertIDFoundAndCurrent(BasicOCSPResponse basicResp, Date validDate, CertID certID)
    {
        return findResponse(basicResp, validDate, certID, false);
    }

    /**
     * Whether a response already held in the cache may answer for certID at validDate - the same
     * question, plus the one the cache adds: does it state a validity interval to reuse it over?
     * <p/>
     * RFC 6960 sec. 4.2.2.1 reads "if nextUpdate is not set, the responder is indicating that newer
     * revocation information is available all the time", so a response without one is never
     * reusable. Nothing is rejected by this: such a response is still used for the check it arrived
     * for, it just costs another request next time rather than being served from here.
     */
    static boolean isCertIDFoundAndReusable(BasicOCSPResponse basicResp, Date validDate, CertID certID)
    {
        return findResponse(basicResp, validDate, certID, true);
    }

    private static boolean findResponse(BasicOCSPResponse basicResp, Date validDate, CertID certID,
        boolean requireNextUpdate)
    {
        ResponseData responseData = ResponseData.getInstance(basicResp.getTbsResponseData());
        ASN1Sequence s = responseData.getResponses();

        for (int i = 0; i != s.size(); i++)
        {
            SingleResponse resp = SingleResponse.getInstance(s.getObjectAt(i));

            if (certID.equals(resp.getCertID()))
            {
                ASN1GeneralizedTime nextUp = resp.getNextUpdate();
                if (nextUp == null && requireNextUpdate)
                {
                    return false;
                }

                try
                {
                    if (nextUp != null && validDate.after(nextUp.getDate()))
                    {
                        return false;
                    }

                    // "Responses whose thisUpdate time is later than the local system time SHOULD
                    // be considered unreliable" - RFC 6960 sec. 4.2.2.1, allowing for clock skew
                    if (isFromTheFuture(resp.getThisUpdate(), validDate))
                    {
                        return false;
                    }
                }
                catch (ParseException e)
                {
                    // this should never happen, but...
                    return false;
                }

                return true;
            }
        }

        return false;
    }

    /**
     * Whether thisUpdate is later than the time being validated for, by more than the clock skew
     * allowed between us and the responder.
     */
    static boolean isFromTheFuture(ASN1GeneralizedTime thisUpdate, Date validDate)
        throws ParseException
    {
        return thisUpdate != null && thisUpdate.getDate().getTime() > (validDate.getTime() + MAX_CLOCK_SKEW_MS);
    }
}
