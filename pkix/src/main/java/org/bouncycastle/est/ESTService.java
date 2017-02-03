package org.bouncycastle.est;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.est.http.*;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;



import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Locale;
import java.util.TimeZone;

/**
 * EST provides unified access to an EST server which is defined as implementing
 * RFC7030.
 */
public class ESTService
{

    private final TLSHostNameAuthorizer hostNameAuthorizer;
    private final String server;
    private final TLSAuthorizer tlsAuthorizer;
    private final ESTHttpClientProvider clientProvider;

    protected final String CACERTS = "/cacerts";
    protected final String SIMPLE_ENROLL = "/simpleenroll";
    protected final String SIMPLE_REENROLL = "/simplereenroll";
    protected final String CSRATTRS = "/csrattrs";


    ESTService(

            TLSHostNameAuthorizer hostNameAuthorizer,
            String server,
            TLSAuthorizer tlsAuthorizer, ESTHttpClientProvider clientProvider)
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

    /**
     * Query the EST server for ca certificates.
     * <p>
     * RFC7030 leans heavily on the verification phases of TLS for both client and server verification.
     * <p>
     * It does however define a bootstrapping mode where if the client does not have the necessary ca certificates to
     * validate the server it can defer to an external source, such as a human, to formally accept the ca certs.
     * <p>
     * Depending on the servers configuration clients may be forced to accept any certificates tendered by the server
     * during the set up phase of TLS, set tlsAcceptAny to true to enable this but remember that it will accept
     * any certificates tended by the server.
     * <p>
     * If callers are using bootstrapping they must examine the CACertsResponse and validate it externally.
     *
     * @return A store of X509Certificates.
     */
    public CACertsResponse getCACerts()
            throws Exception
    {
        ESTHttpResponse resp = null;
        try
        {
            URL url = new URL(server + CACERTS);

            ESTHttpClient client = clientProvider.makeHttpClient();
            ESTHttpRequest req = new ESTHttpRequest("GET", url);
            resp = client.doRequest(req);

            Store<X509CertificateHolder> caCerts;

            if (resp.getStatusCode() == 200)
            {
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence) ain.readObject()));
                caCerts = spkr.getCertificates();
            } else
            {
                throw new ESTHttpException("Get CACerts: " + url.toString(), resp.getStatusCode(), resp.getInputStream(), (int) resp.getContentLength());
            }

            return new CACertsResponse(caCerts, req, resp.getSource());
        } finally
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


        ESTHttpClient client = clientProvider.makeHttpClient();
        ESTHttpResponse resp = client.doRequest(priorResponse.getRequestToRetry());
        return handleEnrollResponse(resp);
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
    public EnrollmentResponse simpleEnroll(boolean reenroll, PKCS10CertificationRequest certificationRequest, ESTHttpAuth auth)
            throws Exception
    {
        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        final byte[] data = annotateRequest(certificationRequest.getEncoded()).getBytes();

        URL url = new URL(server + (reenroll ? SIMPLE_REENROLL : SIMPLE_ENROLL));
        ESTHttpClient client = clientProvider.makeHttpClient();
        ESTHttpRequest req = new ESTHttpRequest("POST", url, new ESTClientRequestInputSource()
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

        ESTHttpResponse resp = client.doRequest(req);
        return handleEnrollResponse(resp);
    }


    protected EnrollmentResponse handleEnrollResponse(ESTHttpResponse resp)
            throws Exception
    {
        try
        {
            ESTHttpRequest req = resp.getOriginalRequest();
            Store<X509CertificateHolder> enrolled = null;
            if (resp.getStatusCode() == 202)
            {
                // Received but not ready.
                String rt = resp.getHeader("Retry-After");
                long notBefore = -1;

                try
                {
                    notBefore = System.currentTimeMillis() + Long.parseLong(rt);
                } catch (NumberFormatException nfe)
                {
                    try
                    {
                        SimpleDateFormat dateFormat = new SimpleDateFormat(
                                "EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
                        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
                        notBefore = dateFormat.parse(rt).getTime();
                    } catch (Exception ex)
                    {
                        throw new ESTHttpException(
                                "Unable to parse Retry-After header:" + req.getUrl().toString() + " " + ex.getMessage(),
                                resp.getStatusCode(), resp.getInputStream(), (int) resp.getContentLength());
                    }
                }

                return new EnrollmentResponse(null, notBefore, req.copy(), resp.getSource());

            } else if (resp.getStatusCode() == 200)
            {
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence) ain.readObject()));
                enrolled = spkr.getCertificates();
                return new EnrollmentResponse(enrolled, -1, null, resp.getSource());
            }

            throw new ESTHttpException(
                    "Simple Enroll: " + req.getUrl().toString(),
                    resp.getStatusCode(), resp.getInputStream(), (int) resp.getContentLength());
        } finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }
    }


    public CSRRequestResponse getCSRAttributes()
            throws Exception
    {

        if (!clientProvider.isTrusted())
        {
            throw new IllegalStateException("No trust anchors.");
        }

        ESTHttpResponse resp = null;
        CSRAttributesResponse response = null;
        try
        {
            URL url = new URL(server + CSRATTRS);

            ESTHttpClient client = clientProvider.makeHttpClient();
            ESTHttpRequest req = new ESTHttpRequest("GET", url);
            resp = client.doRequest(req);


            switch (resp.getStatusCode())
            {
                case 200:
                    ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                    ASN1Sequence seq = (ASN1Sequence) ain.readObject();
                    response = new CSRAttributesResponse(CsrAttrs.getInstance(seq));
                    break;
                case 204:
                    response = null;
                    break;
                case 404:
                    response = null;
                    break;
                default:
                    throw new ESTHttpException(
                            "CSR Attribute request: " + req.getUrl().toString(),
                            resp.getStatusCode(), resp.getInputStream(), (int) resp.getContentLength());
            }

        } finally
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
            } else
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

    public static X509CertificateHolder[] storeToArray(Store<X509CertificateHolder> store)
    {
        return storeToArray(store, null);
    }

    public static X509CertificateHolder[] storeToArray(Store<X509CertificateHolder> store, Selector<X509CertificateHolder> selector)
    {
        Collection<X509CertificateHolder> c = store.getMatches(selector);
        return c.toArray(new X509CertificateHolder[c.size()]);
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
        private final ESTHttpRequest requestToRetry;
        private final Source session;

        public CACertsResponse(Store<X509CertificateHolder> store, ESTHttpRequest requestToRetry, Source session)
        {
            this.store = store;
            this.requestToRetry = requestToRetry;
            this.session = session;
        }

        public Store<X509CertificateHolder> getStore()
        {
            return store;
        }

        public ESTHttpRequest getRequestToRetry()
        {
            return requestToRetry;
        }

        public Object getSession()
        {
            return session.getSession();
        }
    }

    public static class EnrollmentResponse
    {
        private final Store<X509CertificateHolder> store;
        private final long notBefore;
        private final ESTHttpRequest requestToRetry;
        private final Source session;

        public EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTHttpRequest requestToRetry, Source session)
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

        public ESTHttpRequest getRequestToRetry()
        {
            return requestToRetry;
        }

        public Object getSession()
        {
            return session.getSession();
        }
    }

}
