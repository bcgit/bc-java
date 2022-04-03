package org.bouncycastle.est;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

/**
 * ESTService provides unified access to an EST server which is defined as implementing
 * RFC7030.
 */
public class ESTService
{
    protected static final String CACERTS = "/cacerts";
    protected static final String SIMPLE_ENROLL = "/simpleenroll";
    protected static final String SIMPLE_REENROLL = "/simplereenroll";
    protected static final String FULLCMC = "/fullcmc";
    protected static final String SERVERGEN = "/serverkeygen";
    protected static final String CSRATTRS = "/csrattrs";

    protected static final Set<String> illegalParts = new HashSet<String>();

    static
    {
        illegalParts.add(CACERTS.substring(1));
        illegalParts.add(SIMPLE_ENROLL.substring(1));
        illegalParts.add(SIMPLE_REENROLL.substring(1));
        illegalParts.add(FULLCMC.substring(1));
        illegalParts.add(SERVERGEN.substring(1));
        illegalParts.add(CSRATTRS.substring(1));
    }


    private final String server;
    private final ESTClientProvider clientProvider;

    private static final Pattern pathInValid = Pattern.compile("^[0-9a-zA-Z_\\-.~!$&'()*+,;:=]+");

    ESTService(
        String serverAuthority, String label,
        ESTClientProvider clientProvider)
    {

        serverAuthority = verifyServer(serverAuthority);

        if (label != null)
        {
            label = verifyLabel(label);
            server = "https://" + serverAuthority + "/.well-known/est/" + label;
        }
        else
        {
            server = "https://" + serverAuthority + "/.well-known/est";
        }

        this.clientProvider = clientProvider;
    }

    /**
     * Utility method to extract all the X509Certificates from a store and return them in an array.
     *
     * @param store The store.
     * @return An arrar of certificates/
     */
    public static X509CertificateHolder[] storeToArray(Store<X509CertificateHolder> store)
    {
        return storeToArray(store, null);
    }

    /**
     * Utility method to extract all the X509Certificates from a store using a filter and to return them
     * as an array.
     *
     * @param store    The store.
     * @param selector The selector.
     * @return An array of X509Certificates.
     */
    public static X509CertificateHolder[] storeToArray(Store<X509CertificateHolder> store, Selector<X509CertificateHolder> selector)
    {
        Collection<X509CertificateHolder> c = store.getMatches(selector);
        return c.toArray(new X509CertificateHolder[c.size()]);
    }

    /**
     * Query the EST server for ca certificates.
     * <p>
     * RFC7030 leans heavily on the verification phases of TLS for both client and server verification.
     * <p>
     * It does however define a bootstrapping mode where if the client does not have the necessary ca certificates to
     * validate the server it can defer to an external source, such as a human, to formally accept the ca certs.
     * <p>
     * If callers are using bootstrapping they must examine the CACertsResponse and validate it externally.
     *
     * @return A store of X509Certificates.
     */
    public CACertsResponse getCACerts()
        throws ESTException
    {
        ESTResponse resp = null;
        Exception finalThrowable = null;
        CACertsResponse caCertsResponse = null;
        URL url = null;
        boolean failedBeforeClose = false;
        try
        {
            url = new URL(server + CACERTS);

            ESTClient client = clientProvider.makeClient();
            ESTRequest req = new ESTRequestBuilder("GET", url).withClient(client).build();
            resp = client.doRequest(req);

            Store<X509CertificateHolder> caCerts = null;
            Store<X509CRLHolder> crlHolderStore = null;

            if (resp.getStatusCode() == 200)
            {
                String contentType = resp.getHeaders().getFirstValue("Content-Type");
                if (contentType == null || !contentType.startsWith("application/pkcs7-mime"))
                {
                    String j = contentType != null ? " got " + contentType : " but was not present.";
                    throw new ESTException(("Response : " + url.toString() + "Expecting application/pkcs7-mime ") + j, null, resp.getStatusCode(), resp.getInputStream());
                }

                try
                {
                    if (resp.getContentLength() != null && resp.getContentLength() > 0)
                    {
                        ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                        SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));
                        caCerts = spkr.getCertificates();
                        crlHolderStore = spkr.getCRLs();
                    }
                }
                catch (Throwable ex)
                {
                    throw new ESTException("Decoding CACerts: " + url.toString() + " " + ex.getMessage(), ex, resp.getStatusCode(), resp.getInputStream());
                }

            }
            else if (resp.getStatusCode() != 204) // 204 are No Content
            {
                throw new ESTException("Get CACerts: " + url.toString(), null, resp.getStatusCode(), resp.getInputStream());
            }

            caCertsResponse = new CACertsResponse(caCerts, crlHolderStore, req, resp.getSource(), clientProvider.isTrusted());

        }
        catch (Throwable t)
        {
            failedBeforeClose = true;
            if (t instanceof ESTException)
            {
                throw (ESTException)t;
            }
            else
            {
                throw new ESTException(t.getMessage(), t);
            }
        }
        finally
        {
            if (resp != null)
            {
                try
                {
                    resp.close();
                }
                catch (Exception t)
                {
                    finalThrowable = t;
                }
            }
        }

        if (finalThrowable != null)
        {
            if (finalThrowable instanceof ESTException)
            {
                throw (ESTException)finalThrowable;
            }
            throw new ESTException("Get CACerts: " + url.toString(), finalThrowable, resp.getStatusCode(), null);
        }

        return caCertsResponse;
    }

    /**
     * Reissue an existing request where the server had previously returned a 202.
     *
     * @param priorResponse The prior response.
     * @return A new ESTEnrollmentResponse
     * @throws Exception
     */
    public EnrollmentResponse simpleEnroll(EnrollmentResponse priorResponse)
        throws Exception
    {
        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        ESTResponse resp = null;

        try
        {
            ESTClient client = clientProvider.makeClient();
            resp = client.doRequest(new ESTRequestBuilder(priorResponse.getRequestToRetry()).withClient(client).build());
            return handleEnrollResponse(resp);
        }
        catch (Throwable t)
        {
            if (t instanceof ESTException)
            {
                throw (ESTException)t;
            }
            else
            {
                throw new ESTException(t.getMessage(), t);
            }
        }
        finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }
    }

    /**
     * Perform a simple enrollment operation.
     * <p>
     * This method accepts an ESPHttpAuth instance to provide basic or digest authentication.
     * <p>
     * If authentication is to be performed as part of TLS then this instances client keystore and their keystore
     * password need to be specified.
     *
     * @param certificationRequest The certification request.
     * @param auth                 The http auth provider, basic auth or digest auth, can be null.
     * @return The enrolled certificate.
     * @deprecated Use simpleEnroll(EnrollmentOperation operation, PKCS10CertificationRequest certificationRequest, ESTAuth auth)
     */
    @Deprecated
    public EnrollmentResponse simpleEnroll(boolean reenroll, PKCS10CertificationRequest certificationRequest, ESTAuth auth)
        throws IOException
    {
        return simpleEnroll(
                reenroll ? EnrollmentOperation.SIMPLE_REENROLL : EnrollmentOperation.SIMPLE_ENROLL,
                certificationRequest,
                auth);
    }

    /**
     * Perform a simple enrollment operation.
     * <p>
     * This method accepts an ESPHttpAuth instance to provide basic or digest authentication.
     * <p>
     * If authentication is to be performed as part of TLS then this instances client keystore and their keystore
     * password need to be specified.
     *
     * @param certificationRequest The certification request.
     * @param auth                 The http auth provider, basic auth or digest auth, can be null.
     * @return The enrolled certificate.
     */
    public EnrollmentResponse simpleEnroll(EnrollmentOperation operation, PKCS10CertificationRequest certificationRequest, ESTAuth auth)
        throws IOException
    {
        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        ESTResponse resp = null;
        try
        {
            final byte[] data = annotateRequest(certificationRequest.getEncoded()).getBytes();

            URL url = new URL(server + operation.getUriPart());

            ESTClient client = clientProvider.makeClient();
            ESTRequestBuilder req = new ESTRequestBuilder("POST", url).withData(data).withClient(client);

            req.addHeader("Content-Type", "application/pkcs10");
            req.addHeader("Content-Length", "" + data.length);
            req.addHeader("Content-Transfer-Encoding", "base64");

            if (auth != null)
            {
                auth.applyAuth(req);
            }

            resp = client.doRequest(req.build());

            return handleEnrollResponse(resp);

        }
        catch (Throwable t)
        {
            if (t instanceof ESTException)
            {
                throw (ESTException)t;
            }
            else
            {
                throw new ESTException(t.getMessage(), t);
            }
        }
        finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }

    }

    /**
     * Implements Enroll with PoP.
     * Request will have the tls-unique attribute added to it before it is signed and completed.
     *
     * @param reEnroll      True = re enroll.
     * @param builder       The request builder.
     * @param contentSigner The content signer.
     * @param auth          Auth modes.
     * @return Enrollment response.
     * @throws IOException
     * @deprecated use simpleEnrollPoP(EnrollmentOperation operation, final PKCS10CertificationRequestBuilder builder, final ContentSigner contentSigner, ESTAuth auth)
     */
    @Deprecated
    public EnrollmentResponse simpleEnrollPoP(boolean reEnroll, final PKCS10CertificationRequestBuilder builder, final ContentSigner contentSigner, ESTAuth auth)
        throws IOException
    {
        return simpleEnrollPoP(
                reEnroll ? EnrollmentOperation.SIMPLE_REENROLL : EnrollmentOperation.SIMPLE_ENROLL,
                builder,
                contentSigner,
                auth);
    }

    /**
     * Implements Enroll with PoP.
     * Request will have the tls-unique attribute added to it before it is signed and completed.
     *
     * @param operation      enrollment operation.
     * @param builder       The request builder.
     * @param contentSigner The content signer.
     * @param auth          Auth modes.
     * @return Enrollment response.
     * @throws IOException
     */
    public EnrollmentResponse simpleEnrollPoP(EnrollmentOperation operation, final PKCS10CertificationRequestBuilder builder, final ContentSigner contentSigner, ESTAuth auth)
        throws IOException
    {
        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        ESTResponse resp = null;
        try
        {
            URL url = new URL(server + operation.getUriPart());
            ESTClient client = clientProvider.makeClient();

            //
            // Connect supplying a source listener.
            // The source listener is responsible for completing the PCS10 Cert request and encoding it.
            //
            ESTRequestBuilder reqBldr = new ESTRequestBuilder("POST", url).withClient(client).withConnectionListener(new ESTSourceConnectionListener()
            {
                public ESTRequest onConnection(Source source, ESTRequest request)
                    throws IOException
                {
                    //
                    // Add challenge password from tls unique
                    //

                    if (source instanceof TLSUniqueProvider && ((TLSUniqueProvider)source).isTLSUniqueAvailable())
                    {
                        PKCS10CertificationRequestBuilder localBuilder = new PKCS10CertificationRequestBuilder(builder);

                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        byte[] tlsUnique = ((TLSUniqueProvider)source).getTLSUnique();

                        // -DM Base64.toBase64String
                        localBuilder.setAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERPrintableString(Base64.toBase64String(tlsUnique)));
                        bos.write(annotateRequest(localBuilder.build(contentSigner).getEncoded()).getBytes());
                        bos.flush();

                        ESTRequestBuilder reqBuilder = new ESTRequestBuilder(request).withData(bos.toByteArray());

                        reqBuilder.setHeader("Content-Type", "application/pkcs10");
                        reqBuilder.setHeader("Content-Transfer-Encoding", "base64");
                        reqBuilder.setHeader("Content-Length", Long.toString(bos.size()));

                        return reqBuilder.build();
                    }
                    else
                    {
                        throw new IOException("Source does not supply TLS unique.");
                    }
                }
            });

            if (auth != null)
            {
                auth.applyAuth(reqBldr);
            }

            resp = client.doRequest(reqBldr.build());

            return handleEnrollResponse(resp);

        }
        catch (Throwable t)
        {
            if (t instanceof ESTException)
            {
                throw (ESTException)t;
            }
            else
            {
                throw new ESTException(t.getMessage(), t);
            }
        }
        finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }

    }

    /**
     * Handles the enroll response, deals with status codes and setting of delays.
     *
     * @param resp The response.
     * @return An EnrollmentResponse.
     * @throws IOException
     */
    protected EnrollmentResponse handleEnrollResponse(ESTResponse resp)
        throws IOException
    {

        ESTRequest req = resp.getOriginalRequest();
        Store<X509CertificateHolder> enrolled = null;
        PrivateKeyInfo privateKeyInfo = null;

        if (resp.getStatusCode() == 202)
        {
            // Received but not ready.
            String rt = resp.getHeader("Retry-After");

            if (rt == null)
            {
                throw new ESTException("Got Status 202 but not Retry-After header from: " + req.getURL().toString());
            }

            long notBefore = -1;


            try
            {
                notBefore = System.currentTimeMillis() + (Long.parseLong(rt) * 1000);
            }
            catch (NumberFormatException nfe)
            {
                try
                {
                    SimpleDateFormat dateFormat = new SimpleDateFormat(
                        "EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
                    dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
                    notBefore = dateFormat.parse(rt).getTime();
                }
                catch (Exception ex)
                {
                    throw new ESTException(
                        "Unable to parse Retry-After header:" + req.getURL().toString() + " " + ex.getMessage(), null,
                        resp.getStatusCode(), resp.getInputStream());
                }
            }

            return new EnrollmentResponse(null, notBefore, req, resp.getSource());

        }
        else if (resp.getStatusCode() == 200)
        {
            String contentType = resp.getHeader("content-type");
            if (contentType.startsWith("multipart/mixed")) {
                // process multipart response rfc1341
                int boundaryIndex = contentType.indexOf("boundary=");
                if (boundaryIndex == -1) {
                    throw new ESTException("Invalid multipart format. boundary not found");
                }
                String boundary = "--" + contentType.substring(boundaryIndex + "boundary=".length());
                Map<String, String> partsMap = new HashMap<>();

                // Read stream and collect parts
                // there are 3 pieces
                // 1. boundary line
                // 2. headers
                // 3. data
                int state = 1;
                byte[] lineBuffer = new byte[1024];
                String data = "";
                String partContent = "";

                while (true) {
                    String line = readLine(resp.getInputStream(), lineBuffer);

                    if (line == null) {
                        if (state == 3) {
                            partsMap.put(partContent, data);
                        }
                        break;
                    }

                    // check if boundary line
                    if (line.startsWith(boundary)) {
                        switch (state) {
                            case 1:
                                state = 2;
                                break;
                            case 3:
                                // new part started
                                partsMap.put(partContent, data);
                                data = "";
                                partContent="";
                                state = 2;
                                break;
                            default:
                                throw new ESTException("Invalid multipart/mixed format. Empty boundary.");
                        }
                        continue;
                    }

                    switch (state) {
                        case 1:
                            continue;
                        case 2:
                            if (line.isEmpty()) {
                                // headers are completed
                                if (partContent.isEmpty()) {
                                    throw new ESTException("Invalid multipart/mixed format. Content Type not found");
                                }
                                state = 3;
                            } else {
                                // read header
                                int idx = line.indexOf(':');
                                if (idx == -1) {
                                    throw new ESTException("Invalid multipart/mixed format. Invalid headers format");
                                }

                                String header = Strings.toLowerCase(line.substring(0, idx).trim());
                                String value = line.substring(idx + 1).trim();

                                // we care about two headers only
                                if (header.equals("content-type")) {
                                    if (!value.startsWith("application/pkcs8") && !value.startsWith("application/pkcs7")) {
                                        throw new ESTException("Invalid multipart/mixed format. Unsupported content-type: " + value);
                                    }
                                    partContent = value;
                                } else if (header.equals("content-transfer-encoding")) {
                                    if (!value.equals("base64")) {
                                        throw new ESTException("Invalid multipart/mixed format. Unsupported encoding: " + value);
                                    }
                                }
                            }
                            break;
                        case 3:
                            data += line;
                    }
                }

                // store last part
                partsMap.put(partContent, data);

                // now process them
                for (Map.Entry<String, String> entry : partsMap.entrySet()) {
                    try {
                        byte[] decoded = Base64.decode(entry.getValue());

                        if (entry.getKey().startsWith("application/pkcs7")) {
                            // read certificate
                            enrolled = readPkcs7Certificates(new ByteArrayInputStream(decoded));
                        } else {
                            // read private key
                            privateKeyInfo = PrivateKeyInfo.getInstance(decoded);
                        }
                    } catch (Exception ex) {
                        throw new ESTException("Failed to decode part " + entry.getKey(), ex);
                    }
                }
            } else {
                // assume "application/pkcs7-mime; smime-type=certs-only"
                InputStream in = resp.getInputStream();
                enrolled = readPkcs7Certificates(in);
            }
            return new EnrollmentResponse(enrolled, privateKeyInfo, -1, null, resp.getSource());
        }

        throw new ESTException(
            "Simple Enroll: " + req.getURL().toString(), null,
            resp.getStatusCode(), resp.getInputStream());

    }

    private Store<X509CertificateHolder> readPkcs7Certificates(InputStream in) throws IOException {
        Store<X509CertificateHolder> enrolled;
        ASN1InputStream ain = new ASN1InputStream(in);
        SimplePKIResponse spkr = null;
        try {
                spkr = new SimplePKIResponse(ContentInfo.getInstance(ain.readObject()));
        } catch (Exception e) {
                throw new ESTException(e.getMessage(), e.getCause());
            }
            enrolled = spkr.getCertificates();
        return enrolled;
    }

    protected String readLine(InputStream inputStream, byte[] lineBuffer)
            throws IOException
    {
        int c = 0;
        int j;
        do
        {
            j = inputStream.read();
            if (j == -1)
                break;
            lineBuffer[c++] = (byte) j;
            if (c >= lineBuffer.length) {
                throw new IOException("Server sent line > " + lineBuffer.length);
            }
        }
        while (j != '\n');

        if (c == 0)
            return null;
        else
            return new String(lineBuffer, 0, c).trim();
    }

    /**
     * Fetch he CSR Attributes from the server.
     *
     * @return A CSRRequestResponse with the attributes.
     * @throws ESTException
     */
    public CSRRequestResponse getCSRAttributes()
        throws ESTException
    {

        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        ESTResponse resp = null;
        CSRAttributesResponse response = null;
        Exception finalThrowable = null;
        URL url = null;
        try
        {
            url = new URL(server + CSRATTRS);

            ESTClient client = clientProvider.makeClient();
            ESTRequest req = new ESTRequestBuilder("GET", url).withClient(client).build(); //    new ESTRequest("GET", url, null);
            resp = client.doRequest(req);


            switch (resp.getStatusCode())
            {
            case 200:
                try
                {
                    if (resp.getContentLength() != null && resp.getContentLength() > 0)
                    {
                        ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                        ASN1Sequence seq = ASN1Sequence.getInstance(ain.readObject());
                        response = new CSRAttributesResponse(CsrAttrs.getInstance(seq));
                    }
                }
                catch (Throwable ex)
                {
                    throw new ESTException("Decoding CACerts: " + url.toString() + " " + ex.getMessage(), ex, resp.getStatusCode(), resp.getInputStream());
                }

                break;
            case 204:
                response = null;
                break;
            case 404:
                response = null;
                break;
            default:
                throw new ESTException(
                    "CSR Attribute request: " + req.getURL().toString(), null,
                    resp.getStatusCode(), resp.getInputStream());
            }
        }
        catch (Throwable t)
        {

            if (t instanceof ESTException)
            {
                throw (ESTException)t;
            }
            else
            {
                throw new ESTException(t.getMessage(), t);
            }
        }
        finally
        {
            if (resp != null)
            {
                try
                {
                    resp.close();
                }
                catch (Exception ex)
                {
                    finalThrowable = ex;
                }
            }
        }

        if (finalThrowable != null)
        {
            if (finalThrowable instanceof ESTException)
            {
                throw (ESTException)finalThrowable;
            }
            throw new ESTException(finalThrowable.getMessage(), finalThrowable, resp.getStatusCode(), null);
        }

        return new CSRRequestResponse(response, resp.getSource());
    }

    private String annotateRequest(byte[] data)
    {
        int i = 0;
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        // pw.print("-----BEGIN CERTIFICATE REQUEST-----\n");
        do
        {
            // -DM Base64.toBase64String
            // -DM Base64.toBase64String
            if (i + 48 < data.length)
            {
                pw.print(Base64.toBase64String(data, i, 48));
                i += 48;
            }
            else
            {
                pw.print(Base64.toBase64String(data, i, data.length - i));
                i = data.length;
            }
            pw.print('\n');
        }
        while (i < data.length);
        //  pw.print("-----END CERTIFICATE REQUEST-----\n");
        pw.flush();
        return sw.toString();
    }


    private String verifyLabel(String label)
    {
        while (label.endsWith("/") && label.length() > 0)
        {
            label = label.substring(0, label.length() - 1);
        }

        while (label.startsWith("/") && label.length() > 0)
        {
            label = label.substring(1);
        }

        if (label.length() == 0)
        {
            throw new IllegalArgumentException("Label set but after trimming '/' is not zero length string.");
        }

        if (!pathInValid.matcher(label).matches())
        {
            throw new IllegalArgumentException("Server path " + label + " contains invalid characters");
        }

        if (illegalParts.contains(label))
        {
            throw new IllegalArgumentException("Label " + label + " is a reserved path segment.");
        }

        return label;

    }


    private String verifyServer(String server)
    {
        try
        {

            while (server.endsWith("/") && server.length() > 0)
            {
                server = server.substring(0, server.length() - 1);
            }

            if (server.contains("://"))
            {
                throw new IllegalArgumentException("Server contains scheme, must only be <dnsname/ipaddress>:port, https:// will be added arbitrarily.");
            }

            URL u = new URL("https://" + server);
            if (u.getPath().length() == 0 || u.getPath().equals("/"))
            {
                return server;
            }

            throw new IllegalArgumentException("Server contains path, must only be <dnsname/ipaddress>:port, a path of '/.well-known/est/<label>' will be added arbitrarily.");

        }
        catch (Exception ex)
        {
            if (ex instanceof IllegalArgumentException)
            {
                throw (IllegalArgumentException)ex;
            }
            throw new IllegalArgumentException("Scheme and host is invalid: " + ex.getMessage(), ex);
        }

    }
}
