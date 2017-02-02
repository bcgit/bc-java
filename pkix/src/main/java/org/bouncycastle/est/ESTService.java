package org.bouncycastle.est;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.est.http.DefaultESTClient;
import org.bouncycastle.est.http.DefaultESTClientSSLSocketProvider;
import org.bouncycastle.est.http.ESTClientRequestInputSource;
import org.bouncycastle.est.http.ESTHttpAuth;
import org.bouncycastle.est.http.ESTHttpClient;
import org.bouncycastle.est.http.ESTHttpException;
import org.bouncycastle.est.http.ESTHttpRequest;
import org.bouncycastle.est.http.ESTHttpResponse;
import org.bouncycastle.est.http.TLSAcceptedIssuersSource;
import org.bouncycastle.est.http.TLSAuthorizer;
import org.bouncycastle.est.http.TLSHostNameAuthorizer;
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

    private final Set<TrustAnchor> tlsTrustAnchors;
    private final KeyStore clientKeystore;
    private final char[] clientKeystorePassword;
    private final TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private final String server;
    private final TLSAuthorizer<SSLSession> tlsAuthorizer;
    private final CRL revocationList;

    protected final String CACERTS = "/cacerts";
    protected final String SIMPLE_ENROLL = "/simpleenroll";
    protected final String SIMPLE_REENROLL = "/simplereenroll";
    protected final String CSRATTRS = "/csrattrs";


    ESTService(Set<TrustAnchor>
                   tlsTrustAnchors,
               KeyStore clientKeystore,
               char[] clientKeystorePassword,
               TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer,
               String server,
               TLSAuthorizer<SSLSession> tlsAuthorizer, CRL revocationList)
    {
        this.tlsTrustAnchors = tlsTrustAnchors;
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.tlsAuthorizer = tlsAuthorizer;
        this.revocationList = revocationList;
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
     * Use the bootstrapAuthorizer to receive a callback after the ca certificates have been fetched but not returned to
     * the caller to perform any out of band validation, throw an exception to invalidate.
     * <p>
     * Depending on the servers configuration clients may be forced to accept any certificates tendered by the server
     * during the set up phase of TLS, set tlsAcceptAny to true to enable this but remember that it will accept
     * any certificates tended by the server.
     *
     * @param bootstrapAuthorizer The bootstrap authorizer, called when CA need external validation.
     * @param tlsAcceptAny        case the TLS layer to accept any certificates tendered during the TLS negotiation
     *                            phase.
     * @return A store of X509Certificates.
     */
    public Store<X509CertificateHolder> getCACerts(
        RFC7030BootstrapAuthorizer<SSLSession> bootstrapAuthorizer, boolean tlsAcceptAny)
        throws Exception
    {
        ESTHttpResponse resp = null;
        try
        {
            URL url = new URL(server + CACERTS);
            ESTHttpClient client = makeCACertsClient(tlsAcceptAny);
            ESTHttpRequest req = new ESTHttpRequest("GET", url);
            resp = client.doRequest(req);

            Store<X509CertificateHolder> caCerts;

            if (resp.getStatusCode() == 200)
            {
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));
                caCerts = spkr.getCertificates();
                if (bootstrapAuthorizer != null && (tlsTrustAnchors == null || tlsTrustAnchors.isEmpty()))
                {
                    bootstrapAuthorizer.authorise(caCerts, ((SSLSocket)resp.getSocket()).getSession().getPeerCertificateChain(), ((SSLSocket)resp.getSocket()).getSession());
                }
            }
            else
            {
                throw new ESTHttpException("Get CAcerts: " + url.toString(), resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());
            }

            return caCerts;
        }
        finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }
    }


    protected ESTHttpClient makeCACertsClient(final boolean tlsAcceptAny)
        throws Exception
    {

        TLSAcceptedIssuersSource acceptedIssuersSource = (tlsTrustAnchors != null) ? new TLSAcceptedIssuersSource()
        {
            public Set<TrustAnchor> anchors()
            {
                return tlsTrustAnchors;
            }
        } : null;

        TLSAuthorizer<SSLSession> tlsAuthorizer = null;
        if (tlsAcceptAny)
        {
            tlsAuthorizer = new TLSAuthorizer<SSLSession>()
            {
                public void authorize(Set<TrustAnchor> acceptedIssuers, X509Certificate[] chain, String authType)
                    throws CertificateException
                {
                    // Does nothing, failure only occurs when exception is thrown.
                }
            };
        }
        else
        {
            tlsAuthorizer = this.tlsAuthorizer;
        }

        KeyManagerFactory keyFact = null;
        if (clientKeystore != null)
        {
            keyFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyFact.init(clientKeystore, clientKeystorePassword);
        }

        if (tlsAuthorizer == null && acceptedIssuersSource == null)
        {
            return new DefaultESTClient(DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(hostNameAuthorizer));
        }

        if (acceptedIssuersSource != null && tlsAuthorizer == null)
        {
            tlsAuthorizer = DefaultESTClientSSLSocketProvider.getCertPathTLSAuthorizer(revocationList);
        }


        return new DefaultESTClient(
            new DefaultESTClientSSLSocketProvider(acceptedIssuersSource, tlsAuthorizer, keyFact, hostNameAuthorizer));
    }


    /**
     * Reissue an existing request where the server had previously returned a 202.
     *
     * @param priorResponse The prior response.
     * @return A new ESTEnrollmentResponse
     * @throws Exception
     */
    public ESTEnrollmentResponse simpleEnroll(ESTEnrollmentResponse priorResponse)
        throws Exception
    {
        ESTHttpClient client = makeEnrollmentClient();
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
    public ESTEnrollmentResponse simpleEnroll(boolean reenroll, PKCS10CertificationRequest certificationRequest, ESTHttpAuth auth)
        throws Exception
    {
        final byte[] data = annotateRequest(certificationRequest.getEncoded()).getBytes();

        URL url = new URL(server + (reenroll ? SIMPLE_REENROLL : SIMPLE_ENROLL));
        ESTHttpClient client = makeEnrollmentClient();
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


    protected ESTEnrollmentResponse handleEnrollResponse(ESTHttpResponse resp)
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
                        throw new ESTHttpException("Unable to parse Retry-After header:" + req.getUrl().toString() + " " + ex.getMessage(), resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());
                    }
                }

                return new ESTEnrollmentResponse(null, notBefore, req.copy());

            }
            else if (resp.getStatusCode() == 200)
            {
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));
                enrolled = spkr.getCertificates();
                return new ESTEnrollmentResponse(enrolled, -1, null);
            }

            throw new ESTHttpException("Simple Enroll: " + req.getUrl().toString(), resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());
        }
        finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }
    }


    protected ESTHttpClient makeEnrollmentClient()
        throws Exception
    {

        TLSAcceptedIssuersSource acceptedIssuersSource = (tlsTrustAnchors != null) ? new TLSAcceptedIssuersSource()
        {
            public Set<TrustAnchor> anchors()
            {
                return tlsTrustAnchors;
            }
        } : null;

        KeyManagerFactory keyFact = null;
        if (clientKeystore != null)
        {
            keyFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyFact.init(clientKeystore, clientKeystorePassword);
        }

        if (acceptedIssuersSource == null)
        {
            return new DefaultESTClient(DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(hostNameAuthorizer));
        }

        TLSAuthorizer<SSLSession> tlsAuthorizer = this.tlsAuthorizer;

        if (acceptedIssuersSource != null && tlsAuthorizer == null)
        {
            tlsAuthorizer = DefaultESTClientSSLSocketProvider.getCertPathTLSAuthorizer(revocationList);
        }

        return new DefaultESTClient(
            new DefaultESTClientSSLSocketProvider(acceptedIssuersSource, tlsAuthorizer, keyFact, hostNameAuthorizer));

    }


    public CSRAttributesResponse getCSRAttributes()
        throws Exception
    {
        ESTHttpResponse resp = null;
        CSRAttributesResponse response = null;
        try
        {
            URL url = new URL(server + CSRATTRS);

            ESTHttpClient client = makeCSRAttributesClient();
            ESTHttpRequest req = new ESTHttpRequest("GET", url);
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
                throw new ESTHttpException("CSR Attribute request: " + req.getUrl().toString(), resp.getStatusCode(), resp.getInputStream(), (int)resp.getContentLength());
            }

        }
        finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }
        return response;
    }


    /**
     * Makes an client to fetch csr attributes.
     *
     * @return an ESTHttpClient..
     * @throws Exception
     */
    protected ESTHttpClient makeCSRAttributesClient()
        throws Exception
    {

        TLSAcceptedIssuersSource acceptedIssuersSource = (tlsTrustAnchors != null) ? new TLSAcceptedIssuersSource()
        {
            public Set<TrustAnchor> anchors()
            {
                return tlsTrustAnchors;
            }
        } : null;

        KeyManagerFactory keyFact = null;
        if (clientKeystore != null)
        {
            keyFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyFact.init(clientKeystore, clientKeystorePassword);
        }

        if (acceptedIssuersSource == null)
        {
            return new DefaultESTClient(DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(hostNameAuthorizer));
        }


        return new DefaultESTClient(
            new DefaultESTClientSSLSocketProvider(acceptedIssuersSource, tlsAuthorizer, keyFact, hostNameAuthorizer));

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


    public Set<TrustAnchor> getTlsTrustAnchors()
    {
        return tlsTrustAnchors;
    }

    public CRL getRevocationList()
    {
        return revocationList;
    }

    public TLSHostNameAuthorizer<SSLSession> getHostNameAuthorizer()
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


    public static class ESTEnrollmentResponse
    {
        private final Store<X509CertificateHolder> store;
        private final long notBefore;
        private final ESTHttpRequest requestToRetry;

        public ESTEnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTHttpRequest requestToRetry)
        {
            this.store = store;
            this.notBefore = notBefore;
            this.requestToRetry = requestToRetry;
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
    }

}
