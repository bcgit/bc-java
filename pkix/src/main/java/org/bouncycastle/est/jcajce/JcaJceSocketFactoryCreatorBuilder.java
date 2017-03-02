package org.bouncycastle.est.jcajce;


import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
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
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class JcaJceSocketFactoryCreatorBuilder
{
    protected String tlsVersion;
    protected String tlsProvider;
    protected KeyManagerFactory keyManagerFactory;
    protected JcaJceAuthorizer estAuthorizer;
    protected final Set<TrustAnchor> tlsTrustAnchors;
    protected CRL[] revocationLists;

    public JcaJceSocketFactoryCreatorBuilder()
    {
        this.tlsTrustAnchors = null;
    }

    public JcaJceSocketFactoryCreatorBuilder(Set<TrustAnchor> trustAnchors)
    {
        this.tlsTrustAnchors = trustAnchors;
    }


    public JcaJceSocketFactoryCreatorBuilder withTLSVersion(String tlsVersion)
    {
        this.tlsVersion = tlsVersion;
        return this;
    }

    public JcaJceSocketFactoryCreatorBuilder withTLSProvider(String tlsProvider)
    {
        this.tlsProvider = tlsProvider;
        return this;
    }

    public JcaJceSocketFactoryCreatorBuilder withKeyManagerFactory(KeyManagerFactory keyManagerFactory)
    {
        this.keyManagerFactory = keyManagerFactory;
        return this;
    }

    public JcaJceSocketFactoryCreatorBuilder withKeyManagerFactory(
        String type,
        String provider,
        KeyStore clientKeyStore,
        char[] clientKeyStorePass)
        throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException
    {
        if (type == null && provider == null)
        {
            this.keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        }
        else if (provider == null)
        {
            this.keyManagerFactory = KeyManagerFactory.getInstance(type);
        }
        else
        {
            this.keyManagerFactory = KeyManagerFactory.getInstance(type, provider);
        }
        this.keyManagerFactory.init(clientKeyStore, clientKeyStorePass);
        return this;
    }

    public JcaJceSocketFactoryCreatorBuilder setEstAuthorizer(JcaJceAuthorizer estAuthorizer)
    {
        this.estAuthorizer = estAuthorizer;
        return this;
    }

    public JcaJceSocketFactoryCreatorBuilder setRevocationLists(CRL[] revocationLists)
    {
        this.revocationLists = revocationLists;
        return this;
    }

    /**
     * Makes an authorizer that will accept any certificate tendered by the server.
     *
     * @return
     */
    protected JcaJceAuthorizer makeAuthorizerWithoutTrustAnchors()
    {
        return new JcaJceAuthorizer()
        {
            public void authorize(
                X509Certificate[] chain,
                String authType, Set<TrustAnchor> tlsTrustAnchors, CRL[] revocationLists)
                throws CertificateException
            {
                // Does nothing, will accept any and all tendered certificates from the server.
            }
        };
    }

    /**
     * Returns a default CertPath Authorizer.
     *
     * @return
     */
    protected JcaJceAuthorizer makeAuthorizerWithTrustAnchors()
    {

        return new JcaJceAuthorizer()
        {
            public void authorize(X509Certificate[] chain, String authType, Set<TrustAnchor> tlsTrustAnchors, CRL[] revocationLists)
                throws CertificateException
            {
                try
                {
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


    public SocketFactoryCreator build()
    {
        if (tlsTrustAnchors != null && tlsTrustAnchors.isEmpty())
        {
            throw new IllegalStateException("Empty TrustAnchors, must be null or contain one or more TrustAnchors.");
        }


        final X509Certificate[] acceptedIssuers;

        if (tlsVersion == null)
        {
            tlsVersion = "TLS";
        }

        if (estAuthorizer == null)
        {
            if (tlsTrustAnchors == null || tlsTrustAnchors.isEmpty())
            {
                estAuthorizer = makeAuthorizerWithoutTrustAnchors();
            }
            else
            {
                estAuthorizer = makeAuthorizerWithTrustAnchors();
            }
        }

        if (tlsTrustAnchors != null)
        {
            acceptedIssuers = new X509Certificate[tlsTrustAnchors.size()];
            int i = 0;
            for (Iterator<TrustAnchor> it = tlsTrustAnchors.iterator(); it.hasNext(); )
            {
                acceptedIssuers[i++] = it.next().getTrustedCert();
            }
        }
        else
        {
            acceptedIssuers = new X509Certificate[0];
        }


        return new SocketFactoryCreator()
        {

            public boolean isTrusted()
            {
                return tlsTrustAnchors != null && !tlsTrustAnchors.isEmpty();
            }

            public SSLSocketFactory createFactory()
                throws Exception
            {
                SSLContext ctx = null;
                if (tlsProvider != null)
                {
                    ctx = SSLContext.getInstance(tlsVersion, tlsProvider);
                }
                else
                {
                    ctx = SSLContext.getInstance(tlsVersion);
                }


                if (keyManagerFactory == null && estAuthorizer == null)
                {
                    ctx.init(null, null, new SecureRandom());
                    return ctx.getSocketFactory();
                }


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
                        if (estAuthorizer == null)
                        {
                            throw new CertificateException(
                                "No serverTLSAuthorizer specified, if you wish to have no validation then you must supply an instance that does nothing."
                            );
                        }

                        estAuthorizer.authorize(x509Certificates, s, tlsTrustAnchors, revocationLists);
                    }

                    public X509Certificate[] getAcceptedIssuers()
                    {
                        return acceptedIssuers;
                    }
                };

                ctx.init((keyManagerFactory != null) ? keyManagerFactory.getKeyManagers() : null, new TrustManager[]{tm}, new SecureRandom());
                return ctx.getSocketFactory();

            }
        };

    }
}
