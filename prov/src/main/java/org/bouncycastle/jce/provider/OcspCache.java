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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.io.Streams;

class OcspCache
{
    private static final int DEFAULT_TIMEOUT = 15000;
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 32 * 1024;

    private static Map<URI, WeakReference<Map<CertID, OCSPResponse>>> cache
        = Collections.synchronizedMap(new WeakHashMap<URI, WeakReference<Map<CertID, OCSPResponse>>>());

    static OCSPResponse getOcspResponse(
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

                ResponseData responseData = ResponseData.getInstance(basicResp.getTbsResponseData());

                ASN1Sequence s = responseData.getResponses();

                for (int i = 0; i != s.size(); i++)
                {
                    SingleResponse resp = SingleResponse.getInstance(s.getObjectAt(i));

                    if (certID.equals(resp.getCertID()))
                    {
                        ASN1GeneralizedTime nextUp = resp.getNextUpdate();
                        try
                        {
                            if (nextUp != null && parameters.getValidDate().after(nextUp.getDate()))
                            {
                                responseMap.remove(certID);
                                response = null;
                            }
                        }
                        catch (ParseException e)
                        {
                            // this should never happen, but...
                            responseMap.remove(certID);
                            response = null;
                        }
                    }
                }
                if (response != null)
                {
                    return response;
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
            byte[] value = ext.getValue();

            if (OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId().equals(ext.getId()))
            {
                nonce = value;
            }

            requestExtensions.add(new org.bouncycastle.asn1.x509.Extension(
                new ASN1ObjectIdentifier(ext.getId()), ext.isCritical(), value));
        }

        // TODO: configure originator
        TBSRequest tbsReq = new TBSRequest(null, new DERSequence(requests),
            Extensions.getInstance(new DERSequence(requestExtensions)));

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
            int contentLength = ocspCon.getContentLength();
            if (contentLength < 0)
            {
                // TODO: make configurable
                contentLength = DEFAULT_MAX_RESPONSE_SIZE;
            }
            OCSPResponse response = OCSPResponse.getInstance(Streams.readAllLimited(reqIn, contentLength));

            if (OCSPResponseStatus.SUCCESSFUL == response.getResponseStatus().getIntValue())
            {
                boolean validated = false;
                ResponseBytes respBytes = ResponseBytes.getInstance(response.getResponseBytes());

                if (respBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic))
                {
                    BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(respBytes.getResponse().getOctets());

                    validated = ProvOcspRevocationChecker.validatedOcspResponse(basicResp, parameters, nonce, responderCert, helper);
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
            throw new CertPathValidatorException("configuration error: " + e.getMessage(),
                     e, parameters.getCertPath(), parameters.getIndex());
        }
    }
}
