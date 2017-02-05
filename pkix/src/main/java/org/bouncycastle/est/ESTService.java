package org.bouncycastle.est;

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
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cmc.CMCException;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
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
    private final TLSHostNameAuthorizer hostNameAuthorizer;
    private final String server;
    private final TLSAuthorizer tlsAuthorizer;
    private final ESTClientProvider clientProvider;


    ESTService(

        TLSHostNameAuthorizer hostNameAuthorizer,
        String server,
        TLSAuthorizer tlsAuthorizer, ESTClientProvider clientProvider)
    {


        this.hostNameAuthorizer = hostNameAuthorizer;
        this.tlsAuthorizer = tlsAuthorizer;
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
        try
        {
            URL url = new URL(server + CACERTS);

            ESTClient client = clientProvider.makeClient();
            ESTRequest req = new ESTRequest("GET", url);
            resp = client.doRequest(req);

            Store<X509CertificateHolder> caCerts;

            if (resp.getStatusCode() == 200)
            {
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));
                caCerts = spkr.getCertificates();
            }
            else
            {
                throw new ESTException("Get CACerts: " + url.toString(), resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());
            }

            return new CACertsResponse(caCerts, req, resp.getSource(), clientProvider.isTrusted());
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
            ESTRequest req = new ESTRequest("POST", url, new ESTClientRequestInputSource()
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

            if (auth != null)
            {
                req = auth.applyAuth(req);
            }

            resp = client.doRequest(req);
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
                        "Unable to parse Retry-After header:" + req.getUrl().toString() + " " + ex.getMessage(),
                        resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());
                }
            }

            return new EnrollmentResponse(null, notBefore, req.copy(), resp.getSource());

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
            "Simple Enroll: " + req.getUrl().toString(),
            resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());

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
            ESTRequest req = new ESTRequest("GET", url);
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
                    "CSR Attribute request: " + req.getUrl().toString(),
                    resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());
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
        pw.print("-----BEGIN CERTIFICATE REQUEST-----\n");
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
        pw.print("-----END CERTIFICATE REQUEST-----\n");
        pw.flush();
        return sw.toString();
    }

    public TLSHostNameAuthorizer getHostNameAuthorizer()
    {
        return hostNameAuthorizer;
    }

    public static class CSRRequestResponse
    {
        private final CSRAttributesResponse attributesResponse;
        private final Source source;

        public CSRRequestResponse(CSRAttributesResponse attributesResponse, Source session)
        {
            this.attributesResponse = attributesResponse;
            this.source = session;
        }

        public CSRAttributesResponse getAttributesResponse()
        {
            return attributesResponse;
        }

        public Object getSession()
        {
            return source.getSession();
        }
    }


    public static class CACertsResponse
    {
        private final Store<X509CertificateHolder> store;
        private final ESTRequest requestToRetry;
        private final Source session;
        private final boolean trusted;

        public CACertsResponse(Store<X509CertificateHolder> store, ESTRequest requestToRetry, Source session, boolean trusted)
        {
            this.store = store;
            this.requestToRetry = requestToRetry;
            this.session = session;
            this.trusted = trusted;
        }

        public Store<X509CertificateHolder> getStore()
        {
            return store;
        }

        public ESTRequest getRequestToRetry()
        {
            return requestToRetry;
        }

        public Object getSession()
        {
            return session.getSession();
        }

        public boolean isTrusted()
        {
            return trusted;
        }
    }

    public static class EnrollmentResponse
    {
        private final Store<X509CertificateHolder> store;
        private final long notBefore;
        private final ESTRequest requestToRetry;
        private final Source session;

        public EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTRequest requestToRetry, Source session)
        {
            this.store = store;
            this.notBefore = notBefore;
            this.requestToRetry = requestToRetry;
            this.session = session;
        }

        public boolean canRetry()
        {
            return notBefore < System.currentTimeMillis();
        }

        public Store<X509CertificateHolder> getStore()
        {
            return store;
        }

        public long getNotBefore()
        {
            return notBefore;
        }

        public ESTRequest getRequestToRetry()
        {
            return requestToRetry;
        }

        public Object getSession()
        {
            return session.getSession();
        }
    }

}
