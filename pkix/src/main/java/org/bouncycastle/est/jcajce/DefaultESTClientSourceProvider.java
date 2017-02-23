package org.bouncycastle.est.jcajce;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.est.ESTClientSourceProvider;
import org.bouncycastle.est.Source;
import org.bouncycastle.util.Strings;

public class DefaultESTClientSourceProvider
    implements ESTClientSourceProvider
{

    private final SSLSocketFactory sslSocketFactory;
    private final JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private final int timeout;
    private final ChannelBindingProvider bindingProvider;
    private final Set<String> cipherSuites;
    private final Long absoluteLimit;


    public DefaultESTClientSourceProvider(
        SSLSocketFactory socketFactory,
        JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer,
        int timeout, ChannelBindingProvider bindingProvider,
        Set<String> cipherSuites, Long absoluteLimit)
        throws GeneralSecurityException
    {
        this.sslSocketFactory = socketFactory;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.timeout = timeout;
        this.bindingProvider = bindingProvider;
        this.cipherSuites = cipherSuites;
        this.absoluteLimit = absoluteLimit;
    }

    public static JcaJceAuthorizer getCertPathTLSAuthorizer(final CRL[] revocationLists, final Set<TrustAnchor> tlsTrustAnchors)
    {
        return new JcaJceAuthorizer()
        {
            public void authorize(X509Certificate[] chain, String authType)
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


                    PKIXBuilderParameters param = new PKIXBuilderParameters(tlsTrustAnchors, constraints);
                    param.addCertStore(certStore);
                    if (revocationLists != null)
                    {
                        param.setRevocationEnabled(true);
                        param.addCertStore(
                            CertStore.getInstance(
                                "Collection",
                                new CollectionCertStoreParameters(Arrays.asList(revocationLists)
                                )));
                    }
                    else
                    {
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


    public Source makeSource(String host, int port)
        throws IOException
    {
        SSLSocket sock = (SSLSocket)sslSocketFactory.createSocket(host, port);
        if (cipherSuites != null && !cipherSuites.isEmpty())
        {
            sock.setEnabledCipherSuites(cipherSuites.toArray(new String[cipherSuites.size()]));
        }

        sock.setSoTimeout(timeout);
        sock.setUseClientMode(true);
        sock.startHandshake();

        if (sock.getSession().getProtocol().equalsIgnoreCase("tlsv1"))
        {
            try
            {
                sock.close();
            }
            catch (Exception ex)
            {
                // Deliberately ignored.
            }
            throw new IOException("EST clients must not use TLSv1");
        }

        // check for use of null cipher and fail.
        if (Strings.toLowerCase(sock.getSession().getCipherSuite()).contains("with null")) {
            throw new IOException("EST clients must not use NULL ciphers");
        }


        if (hostNameAuthorizer != null && !hostNameAuthorizer.verified(host, sock.getSession()))
        {
            throw new IOException("Hostname was not verified: " + host);
        }
        return new SSLSocketSource(sock, bindingProvider, absoluteLimit);
    }
}
