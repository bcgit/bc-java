package org.bouncycastle.est.jcajce;


import org.bouncycastle.est.*;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

public class DefaultESTClientSSLSocketProvider
    implements ESTClientSSLSocketProvider
{

    private final TLSAcceptedIssuersSource tlsAcceptedIssuersSource;
    private final TLSAuthorizer serverTLSAuthorizer;
    private final KeyManagerFactory keyManagerFactory;
    private final TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;


    private SSLSocketFactory sslSocketFactory;

    public DefaultESTClientSSLSocketProvider(
        TLSAcceptedIssuersSource tlsAcceptedIssuersSource,
        TLSAuthorizer serverTLSAuthorizer,
        KeyManagerFactory keyManagerFactory,
        TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)
        throws Exception
    {
        this.tlsAcceptedIssuersSource = tlsAcceptedIssuersSource;
        this.serverTLSAuthorizer = serverTLSAuthorizer;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.keyManagerFactory = keyManagerFactory;
        sslSocketFactory = createFactory();
    }

    /**
     * Return an ESTClientSSLSocketProvider that uses the the default SSLSocketProvider and a host name verifier.
     *
     * @param hostNameAuthorizer The host name authorizer. (Can be null for no hostname verification.)
     * @return ESTClientSSLSocketProvider
     * @throws Exception
     */
    public static ESTClientSSLSocketProvider getUsingDefaultSSLSocketFactory(TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)
        throws Exception
    {
        return new DefaultESTClientSSLSocketProvider(null, null, null, hostNameAuthorizer)
        {
            @Override
            public SSLSocketFactory createFactory()
                throws Exception
            {
                return (SSLSocketFactory)SSLSocketFactory.getDefault();
            }
        };
    }

    /**
     * Return an ESTClientSSLSocketProvider that uses the the default SSLSocketProvider and a host name verifier.
     *
     * @param keyManagerFactory  The keymanager factory supplying the client keys.
     * @param hostNameAuthorizer The host name authorizer. (Can be null for no hostname verification.)
     * @return ESTClientSSLSocketProvider
     * @throws Exception
     */
    public static ESTClientSSLSocketProvider getUsingDefaultSSLSocketFactory(KeyManagerFactory keyManagerFactory, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)
        throws Exception
    {
        return new DefaultESTClientSSLSocketProvider(null, null, keyManagerFactory, hostNameAuthorizer)
        {
            @Override
            public SSLSocketFactory createFactory()
                throws Exception
            {
                return (SSLSocketFactory)SSLSocketFactory.getDefault();
            }
        };
    }


    /**
     * Creates the SSLSocketFactory.
     *
     * @return A SSLSocketFactory instance.
     * @throws Exception
     */
    public SSLSocketFactory createFactory()
        throws Exception
    {
        SSLContext ctx = SSLContext.getInstance("TLS");
        X509TrustManager tm = new X509TrustManager()
        {
            public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
                throws CertificateException
            {
                // For clients.
            }

            public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                throws CertificateException
            {
                if (serverTLSAuthorizer == null)
                {
                    throw new CertificateException(
                        "No serverTLSAuthorizer specified, if you wish to have no validation then you must supply an instance that does nothing."
                    );
                }

                serverTLSAuthorizer.authorize(tlsAcceptedIssuersSource != null ? tlsAcceptedIssuersSource.anchors() : null, x509Certificates, s);
            }

            public X509Certificate[] getAcceptedIssuers()
            {
                if (tlsAcceptedIssuersSource != null)
                {
                    Set<TrustAnchor> tas = tlsAcceptedIssuersSource.anchors();
                    X509Certificate[] c = new X509Certificate[tas.size()];
                    int j = 0;
                    for (Iterator it = tas.iterator(); it.hasNext(); )
                    {
                        TrustAnchor ta = (TrustAnchor)it.next();
                        c[j++] = ta.getTrustedCert();
                    }
                    return c;
                }
                return new X509Certificate[0];
            }
        };

        ctx.init((keyManagerFactory != null) ? keyManagerFactory.getKeyManagers() : null, new TrustManager[]{tm}, new SecureRandom());
        return ctx.getSocketFactory();
    }


    public static TLSAuthorizer<SSLSession> getCertPathTLSAuthorizer(final CRL revocationList)
    {
        // TODO must accept array of revocation lists.

        return new TLSAuthorizer<SSLSession>()
        {
            public void authorize(Set<TrustAnchor> acceptedIssuers, X509Certificate[] chain, String authType)
                throws CertificateException
            {
                try
                {
                    // From BC JSSE.
                    // TODO Review.
                    CertStore certStore = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(Arrays.asList(chain)), "BC");

                    CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");

                    X509CertSelector constraints = new X509CertSelector();

                    constraints.setCertificate(chain[0]);


                    PKIXBuilderParameters param = new PKIXBuilderParameters(acceptedIssuers, constraints);
                    param.addCertStore(certStore);
                    if (revocationList != null) {
                        param.setRevocationEnabled(true);
                        param.addCertStore(
                                CertStore.getInstance(
                                        "Collection",
                                        new CollectionCertStoreParameters(Arrays.asList(revocationList)
                                        )));
                    } else {
                        param.setRevocationEnabled(false);
                    }

                    PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)pathBuilder.build(param);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CertificateException("unable to process certificates: " + e.getMessage(), e);
                }
            }
        };
    }


    public Source wrapSocket(Socket plainSocket, String host, int port)
        throws Exception
    {
        SSLSocket sock = (SSLSocket)sslSocketFactory.createSocket(plainSocket, host, port, true);
        sock.setUseClientMode(true);
        sock.startHandshake();
        if (hostNameAuthorizer != null && !hostNameAuthorizer.authorise(host, sock.getSession()))
        {
            throw new IOException("Hostname was not verified: " + host);
        }
        return new SSLSocketSource(sock);
    }
}
