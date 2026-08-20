package org.bouncycastle.jsse.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
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
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.io.StreamOverflowException;
import org.bouncycastle.util.io.Streams;

/**
 * Fetches stapling responses over HTTP, per RFC 6960 Appendix A.1.
 * <p/>
 * The request is unsigned, as RFC 6960 sec. 4.1.2 permits and as the JDK's own OCSP client sends it.
 * The response is <b>not</b> validated - see {@link OcspStaple} for why a stapling server does not
 * verify what it relays - but it is checked for being an answer about the certificate asked about:
 * a response carrying no SingleResponse for <code>certID</code> is discarded rather than stapled,
 * since neither we nor the client could bind it to the certificate.
 */
class OcspStapleHttpFetcher
    implements OcspStapleFetcher
{
    private static final Logger LOG = Logger.getLogger(OcspStapleHttpFetcher.class.getName());

    private static final int DEFAULT_MAX_RESPONSE_SIZE = 64 * 1024;

    private static final int READ_BLOCK_SIZE = 4096;

    private final URI responderOverride;
    private final int responseTimeoutMs;

    /**
     * @param responderOverride responder to use in place of the one named by each certificate's AIA
     *                          extension, or null to always use the AIA.
     * @param responseTimeoutMs how long one fetch may take in total, in milliseconds. Must be
     *                          positive: this runs on a handshake thread, so "wait indefinitely" is
     *                          not an option here.
     */
    OcspStapleHttpFetcher(URI responderOverride, int responseTimeoutMs)
    {
        if (responseTimeoutMs < 1)
        {
            throw new IllegalArgumentException("'responseTimeoutMs' must be positive");
        }

        this.responderOverride = responderOverride;
        this.responseTimeoutMs = responseTimeoutMs;
    }

    public OcspStaple fetch(CertID certID, X509Certificate cert, Extensions requestExtensions)
        throws IOException
    {
        /*
         * RFC 6960 sec. 4.2.2.2.1. A certificate carrying id-pkix-ocsp-nocheck is one whose issuer
         * has undertaken not to publish status for it, so there is nothing to ask for.
         */
        if (null != cert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()))
        {
            if (LOG.isLoggable(Level.FINER))
            {
                LOG.finer("No stapling for a certificate with id-pkix-ocsp-nocheck: "
                    + cert.getSubjectX500Principal());
            }
            return null;
        }

        URL responderUrl = getResponderURL(cert);
        if (null == responderUrl)
        {
            if (LOG.isLoggable(Level.FINER))
            {
                LOG.finer("No OCSP responder for certificate: " + cert.getSubjectX500Principal());
            }
            return null;
        }

        byte[] request = createRequest(certID, requestExtensions);

        if (LOG.isLoggable(Level.FINER))
        {
            LOG.finer("Requesting stapling response from " + responderUrl + " for certificate: "
                + cert.getSubjectX500Principal());
        }

        OCSPResponse response = post(responderUrl, request);

        int responseStatus = response.getResponseStatus().getIntValue();
        if (OCSPResponseStatus.SUCCESSFUL != responseStatus)
        {
            // tryLater, malformedRequest and the rest: nothing to staple, and not our error to fix
            LOG.fine("OCSP responder " + responderUrl + " returned status " + responseStatus
                + " for certificate: " + cert.getSubjectX500Principal());
            return null;
        }

        return createStaple(certID, cert, responderUrl, response);
    }

    private OcspStaple createStaple(CertID certID, X509Certificate cert, URL responderUrl, OCSPResponse response)
    {
        ResponseBytes responseBytes = response.getResponseBytes();
        if (null == responseBytes
            || !OCSPObjectIdentifiers.id_pkix_ocsp_basic.equals(responseBytes.getResponseType()))
        {
            LOG.fine("OCSP responder " + responderUrl + " returned a successful response that is not a"
                + " BasicOCSPResponse; not stapling for certificate: " + cert.getSubjectX500Principal());
            return null;
        }

        SingleResponse singleResponse = findSingleResponse(certID, responseBytes);
        if (null == singleResponse)
        {
            /*
             * Either the responder answered about something else, or it echoed our CertID with a
             * different hashAlgorithm than we asked with. Neither can be bound to this certificate
             * without redoing the CertID, so there is nothing here worth relaying.
             */
            LOG.fine("OCSP responder " + responderUrl + " returned no response for the certificate asked"
                + " about; not stapling for certificate: " + cert.getSubjectX500Principal());
            return null;
        }

        Date thisUpdate, nextUpdate;
        try
        {
            ASN1GeneralizedTime nextUp = singleResponse.getNextUpdate();

            thisUpdate = singleResponse.getThisUpdate().getDate();
            nextUpdate = null == nextUp ? null : nextUp.getDate();
        }
        catch (ParseException e)
        {
            LOG.log(Level.FINE, "Unparseable time in OCSP response from " + responderUrl, e);
            return null;
        }

        if (1 == singleResponse.getCertStatus().getTagNo())
        {
            /*
             * Relayed as-is: the client is entitled to be told, and suppressing it would only mean
             * the client asks the responder itself. Logged loudly because it is not something a
             * server operator would want to discover from a client's error report.
             */
            LOG.warning("OCSP responder " + responderUrl + " reports revoked for the certificate being"
                + " stapled: " + cert.getSubjectX500Principal());
        }

        return new OcspStaple(response, thisUpdate, nextUpdate);
    }

    private static SingleResponse findSingleResponse(CertID certID, ResponseBytes responseBytes)
    {
        BasicOCSPResponse basicResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
        ResponseData responseData = ResponseData.getInstance(basicResponse.getTbsResponseData());
        ASN1Sequence responses = responseData.getResponses();

        for (int i = 0; i != responses.size(); i++)
        {
            SingleResponse singleResponse = SingleResponse.getInstance(responses.getObjectAt(i));

            if (certID.equals(singleResponse.getCertID()))
            {
                return singleResponse;
            }
        }

        return null;
    }

    private byte[] createRequest(CertID certID, Extensions requestExtensions)
        throws IOException
    {
        ASN1EncodableVector requests = new ASN1EncodableVector();
        requests.add(new Request(certID, null));

        TBSRequest tbsRequest = new TBSRequest(null, new DERSequence(requests), requestExtensions);

        // no requestorName and no signature - see RFC 6960 sec. 4.1.2
        return new OCSPRequest(tbsRequest, null).getEncoded(ASN1Encoding.DER);
    }

    private URL getResponderURL(X509Certificate cert)
    {
        if (null != responderOverride)
        {
            return toHttpURL(responderOverride.toString());
        }

        byte[] extValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (null == extValue)
        {
            return null;
        }

        AuthorityInformationAccess aia;
        try
        {
            aia = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(extValue).getOctets());
        }
        catch (RuntimeException e)
        {
            LOG.log(Level.FINE, "Unparseable authorityInfoAccess extension", e);
            return null;
        }

        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
        for (int i = 0; i != accessDescriptions.length; i++)
        {
            AccessDescription accessDescription = accessDescriptions[i];
            if (!AccessDescription.id_ad_ocsp.equals(accessDescription.getAccessMethod()))
            {
                continue;
            }

            GeneralName accessLocation = accessDescription.getAccessLocation();
            if (GeneralName.uniformResourceIdentifier != accessLocation.getTagNo())
            {
                continue;
            }

            URL url = toHttpURL(((ASN1String)accessLocation.getName()).getString());
            if (null != url)
            {
                return url;
            }
        }

        return null;
    }

    /**
     * RFC 6960 Appendix A defines OCSP over HTTP, so anything else named in an AIA extension - or
     * misconfigured as the responder override - is not something to open a connection to.
     */
    private static URL toHttpURL(String uri)
    {
        try
        {
            URL url = new URL(uri);
            String protocol = url.getProtocol();

            if ("http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol))
            {
                return url;
            }

            LOG.fine("Ignoring non-HTTP OCSP responder URI: " + uri);
        }
        catch (Exception e)
        {
            LOG.log(Level.FINE, "Ignoring unusable OCSP responder URI: " + uri, e);
        }

        return null;
    }

    /**
     * The connect and read timeouts are set to the whole budget as a backstop, but a read timeout is
     * per <code>read()</code> - a responder that accepts the connection and then trickles bytes would
     * satisfy it indefinitely - so the elapsed time is tracked against a deadline of its own. A read
     * already in flight when the deadline passes still has to return first, which is what bounds the
     * whole fetch at twice <code>responseTimeoutMs</code> rather than exactly it.
     */
    private OCSPResponse post(URL responderUrl, byte[] request)
        throws IOException
    {
        long deadlineMs = System.currentTimeMillis() + responseTimeoutMs;

        HttpURLConnection connection = null;
        try
        {
            connection = (HttpURLConnection)responderUrl.openConnection();
            connection.setConnectTimeout(responseTimeoutMs);
            connection.setReadTimeout(responseTimeoutMs);
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-type", "application/ocsp-request");
            connection.setRequestProperty("Content-length", String.valueOf(request.length));

            OutputStream requestOut = connection.getOutputStream();
            requestOut.write(request);
            requestOut.flush();

            InputStream responseIn = connection.getInputStream();

            byte[] response = readResponse(responseIn, connection.getContentLength(), deadlineMs,
                responderUrl);

            return OCSPResponse.getInstance(response);
        }
        catch (RuntimeException e)
        {
            // an unparseable response is the responder's problem, reported like an unreachable one
            throw Exceptions.ioException("unable to read OCSP response from " + responderUrl + ": "
                + e.getMessage(), e);
        }
        finally
        {
            if (null != connection)
            {
                // closes the underlying socket, so a read blocked past the deadline cannot linger
                connection.disconnect();
            }
        }
    }

    /**
     * Read the response, up to the size limit and no further than the deadline. Restates
     * {@link Streams#readAllLimited(InputStream, int)}'s bare "Data Overflow" in terms of the limit
     * and the property that sets it, as {@link org.bouncycastle.util.Properties#OCSP_MAX_RESPONSE_SIZE}
     * is shared with the CertPath validator's own reader.
     */
    private static byte[] readResponse(InputStream responseIn, int contentLength, long deadlineMs,
        URL responderUrl)
        throws IOException
    {
        int responseSizeLimit = getResponseSizeLimit(contentLength);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] block = new byte[READ_BLOCK_SIZE];

        long total = 0;
        for (;;)
        {
            if (System.currentTimeMillis() >= deadlineMs)
            {
                throw new IOException("timed out reading an OCSP response from " + responderUrl);
            }

            int count = responseIn.read(block, 0, block.length);
            if (count < 0)
            {
                return buf.toByteArray();
            }

            total += count;
            if (total > responseSizeLimit)
            {
                throw new StreamOverflowException("OCSP response exceeds " + responseSizeLimit
                    + " bytes (see " + Properties.OCSP_MAX_RESPONSE_SIZE + ")");
            }

            buf.write(block, 0, count);
        }
    }

    /**
     * How many bytes we are prepared to read: the responder's declared Content-Length where it has
     * given one and it is no larger than our own ceiling, that ceiling otherwise. The declared
     * length is the responder's to choose, so it may narrow the read but never widen it.
     * <p/>
     * NOTE: keep in step with the CertPath validator's OcspCache.getResponseSizeLimit.
     */
    private static int getResponseSizeLimit(int contentLength)
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
}
