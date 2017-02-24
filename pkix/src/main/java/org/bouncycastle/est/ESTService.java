package org.bouncycastle.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Locale;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cmc.CMCException;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

/**
 * EST provides unified access to an EST server which is defined as implementing
 * RFC7030.
 */
public class ESTService
{

    protected final String CACERTS = "/cacerts";
    protected final String SIMPLE_ENROLL = "/simpleenroll";
    protected final String SIMPLE_REENROLL = "/simplereenroll";
    protected final String CSRATTRS = "/csrattrs";
    private final String server;
    private final ESTClientProvider clientProvider;


    ESTService(
        String server,
        ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        if (server.endsWith("/"))
        {
            server = server.substring(0, server.length() - 1); // Trim off trailing slash
        }
        this.server = server;
    }

    public static X509CertificateHolder[] storeToArray(Store<X509CertificateHolder> store)
    {
        return storeToArray(store, null);
    }

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
        throws Exception
    {
        ESTResponse resp = null;
        Exception finalThrowable = null;
        CACertsResponse caCertsResponse = null;
        URL url = null;
        try
        {
            url = new URL(server + CACERTS);

            ESTClient client = clientProvider.makeClient();
            ESTRequest req = new ESTRequestBuilder("GET", url, null).withESTClient(client).build();
            resp = client.doRequest(req);

            Store<X509CertificateHolder> caCerts = null;
            Store<X509CRLHolder> crlHolderStore = null;


            if (resp.getStatusCode() == 200)
            {
                if (!"application/pkcs7-mime".equals(resp.getHeaders().getFirstValue("Content-Type")))
                {
                    String j = resp.getHeaders().getFirstValue("Content-Type") != null ? " got " + resp.getHeaders().getFirstValue("Content-Type") : " but was not present.";
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
                throw finalThrowable;
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
            resp = client.doRequest(priorResponse.getRequestToRetry());
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
     */
    public EnrollmentResponse simpleEnroll(boolean reenroll, PKCS10CertificationRequest certificationRequest, ESTAuth auth)
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

            URL url = new URL(server + (reenroll ? SIMPLE_REENROLL : SIMPLE_ENROLL));
            ESTClient client = clientProvider.makeClient();
            ESTRequestBuilder req = new ESTRequestBuilder("POST", url, null).withClientRequestIdempotentInputSource(new ESTClientRequestIdempotentInputSource()
            {
                public void ready(OutputStream os)
                    throws IOException
                {
                    os.write(data);
                    os.flush();
                }
            });

            req.addHeader("Content-Type", "application/pkcs10");
            req.addHeader("content-length", "" + data.length);
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
     */
    public EnrollmentResponse simpleEnrollPoP(boolean reEnroll, final PKCS10CertificationRequestBuilder builder, final ContentSigner contentSigner, ESTAuth auth)
        throws IOException
    {
        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        ESTResponse resp = null;
        try
        {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            URL url = new URL(server + (reEnroll ? SIMPLE_REENROLL : SIMPLE_ENROLL));
            ESTClient client = clientProvider.makeClient();

            //
            // Connect supplying a source listener.
            // The source listener is responsible for completing the PCS10 Cert request and encoding it.
            //
            ESTRequestBuilder reqBldr = new ESTRequestBuilder("POST", url, new ESTSourceConnectionListener()
            {
                public ESTRequest onConnection(Source source, ESTRequest request)
                    throws IOException
                {
                    //
                    // Add challenge password from tls unique
                    //

                    if (source instanceof TLSUniqueProvider)
                    {
                        bos.reset();
                        byte[] tlsUnique = ((TLSUniqueProvider)source).getTLSUnique();

                        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERPrintableString(Base64.toBase64String(tlsUnique)));
                        bos.write(annotateRequest(builder.build(contentSigner).getEncoded()).getBytes());
                        bos.flush();

                        ESTRequestBuilder reqBuilder = new ESTRequestBuilder(request);

                        reqBuilder.setHeader("Content-Length", Long.toString(bos.size()));

                        return reqBuilder.build();
                    }
                    else
                    {
                        throw new IOException("Source does not supply TLS unique.");
                    }
                }
            })
                .withClientRequestIdempotentInputSource(new ESTClientRequestIdempotentInputSource()
                {
                    public void ready(OutputStream os)
                        throws IOException
                    {
                        os.write(bos.toByteArray());
                        os.flush();
                    }
                });

            reqBldr.addHeader("Content-Type", "application/pkcs10");
            reqBldr.addHeader("Content-Transfer-Encoding", "base64");

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


    protected EnrollmentResponse handleEnrollResponse(ESTResponse resp)
        throws IOException
    {

        ESTRequest req = resp.getOriginalRequest();
        Store<X509CertificateHolder> enrolled = null;
        if (resp.getStatusCode() == 202)
        {
            // Received but not ready.
            String rt = resp.getHeader("Retry-After");
            long notBefore = -1;

            try
            {
                notBefore = System.currentTimeMillis() + Long.parseLong(rt);
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
                        "Unable to parse Retry-After header:" + req.getUrl().toString() + " " + ex.getMessage(), null,
                        resp.getStatusCode(), resp.getInputStream());
                }
            }

            return new EnrollmentResponse(null, notBefore, req, resp.getSource());

        }
        else if (resp.getStatusCode() == 200)
        {
            ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
            SimplePKIResponse spkr = null;
            try
            {
                spkr = new SimplePKIResponse(ContentInfo.getInstance(ain.readObject()));
            }
            catch (CMCException e)
            {
                throw new ESTException(e.getMessage(), e.getCause());
            }
            enrolled = spkr.getCertificates();
            return new EnrollmentResponse(enrolled, -1, null, resp.getSource());
        }

        throw new ESTException(
            "Simple Enroll: " + req.getUrl().toString(), null,
            resp.getStatusCode(), resp.getInputStream());

    }

    public CSRRequestResponse getCSRAttributes()
        throws IOException
    {

        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        ESTResponse resp = null;
        CSRAttributesResponse response = null;
        try
        {
            URL url = new URL(server + CSRATTRS);

            ESTClient client = clientProvider.makeClient();
            ESTRequest req = new ESTRequestBuilder("GET", url, null).withESTClient(client).build(); //    new ESTRequest("GET", url, null);
            resp = client.doRequest(req);


            switch (resp.getStatusCode())
            {
            case 200:
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                ASN1Sequence seq = (ASN1Sequence)ain.readObject();
                response = new CSRAttributesResponse(CsrAttrs.getInstance(seq));
                break;
            case 204:
                response = null;
                break;
            case 404:
                response = null;
                break;
            default:
                throw new ESTException(
                    "CSR Attribute request: " + req.getUrl().toString(), null,
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
                resp.close();
            }
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


}
