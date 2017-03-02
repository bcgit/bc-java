package org.bouncycastle.est.jcajce;


import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

public class JcaJceSocketFactoryCreatorBuilder
{
    protected String tlsVersion = "TLS";
    protected String tlsProvider;
    protected KeyManagerFactory keyManagerFactory;
    protected X509TrustManager[] trustManagers;
    protected CRL[] revocationLists;


    public JcaJceSocketFactoryCreatorBuilder(X509TrustManager trustManager)
    {
        if (trustManager == null)
        {
            this.trustManagers = null;
            return;
        }
        this.trustManagers = new X509TrustManager[]{trustManager};
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




    public JcaJceSocketFactoryCreatorBuilder setRevocationLists(CRL[] revocationLists)
    {
        this.revocationLists = revocationLists;
        return this;
    }

    public SocketFactoryCreator build()
    {
        if (trustManagers == null)
        {
            throw new IllegalStateException("Trust managers can not be null");
        }


        return new SocketFactoryCreator()
        {

            public boolean isTrusted()
            {
                for (X509TrustManager tm : trustManagers)
                {
                    if (tm.getAcceptedIssuers().length > 0)
                    {
                        return true;
                    }
                }

                return false;
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


                ctx.init((keyManagerFactory != null) ? keyManagerFactory.getKeyManagers() : null, trustManagers, new SecureRandom());
                return ctx.getSocketFactory();

            }
        };

    }
}
