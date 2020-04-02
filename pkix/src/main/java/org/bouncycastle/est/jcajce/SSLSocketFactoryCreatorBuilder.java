package org.bouncycastle.est.jcajce;


import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A basic builder to allow configuration of an SSLContext used to create an SSLSocketFactory.
 */
class SSLSocketFactoryCreatorBuilder
{
    protected String tlsVersion = "TLS";
    protected Provider tlsProvider;
    protected KeyManager[] keyManagers;
    protected X509TrustManager[] trustManagers;
    protected SecureRandom secureRandom;

    public SSLSocketFactoryCreatorBuilder(X509TrustManager trustManager)
    {
        if (trustManager == null)
        {
            throw new NullPointerException("Trust managers can not be null");
        }
        this.trustManagers = new X509TrustManager[]{trustManager};
    }

    public SSLSocketFactoryCreatorBuilder(X509TrustManager[] trustManagers)
    {
        if (trustManagers == null)
        {
            throw new NullPointerException("Trust managers can not be null");
        }
        this.trustManagers = trustManagers;
    }

    public SSLSocketFactoryCreatorBuilder withTLSVersion(String tlsVersion)
    {
        this.tlsVersion = tlsVersion;
        return this;
    }

    public SSLSocketFactoryCreatorBuilder withSecureRandom(SecureRandom secureRandom)
    {
        this.secureRandom = secureRandom;
        return this;
    }

    /**
     * Configure this builder to use the provider with the passed in name.
     *
     * @param tlsProviderName the name JSSE Provider to use.
     * @return the current builder instance.
     * @throws NoSuchProviderException if the specified provider does not exist.
     */
    public SSLSocketFactoryCreatorBuilder withProvider(String tlsProviderName)
        throws NoSuchProviderException
    {
        this.tlsProvider = Security.getProvider(tlsProviderName);
        if (this.tlsProvider == null)
        {
            throw new NoSuchProviderException("JSSE provider not found: " + tlsProviderName);
        }
        return this;
    }

    /**
     * Configure this builder to use the passed in provider.
     *
     * @param tlsProvider the JSSE Provider to use.
     * @return the current builder instance.
     */
    public SSLSocketFactoryCreatorBuilder withProvider(Provider tlsProvider)
    {
        this.tlsProvider = tlsProvider;
        return this;
    }

    public SSLSocketFactoryCreatorBuilder withKeyManager(KeyManager keyManager)
    {
        if (keyManager == null)
        {
            this.keyManagers = null;
        }
        else
        {
            this.keyManagers = new KeyManager[]{keyManager};
        }
        return this;
    }

    public SSLSocketFactoryCreatorBuilder withKeyManagers(KeyManager[] keyManagers)
    {
        this.keyManagers = keyManagers;

        return this;
    }

    public SSLSocketFactoryCreator build()
    {
        return new SSLSocketFactoryCreator()
        {
            public boolean isTrusted()
            {
                for (int i = 0; i != trustManagers.length; i++)
                {
                    X509TrustManager tm = trustManagers[i];
                    if (tm.getAcceptedIssuers().length > 0)
                    {
                        return true;
                    }
                }

                return false;
            }

            public SSLSocketFactory createFactory()
                throws NoSuchAlgorithmException, NoSuchProviderException, KeyManagementException
            {
                SSLContext ctx;

                if (tlsProvider != null)
                {
                    ctx = SSLContext.getInstance(tlsVersion, tlsProvider);
                }
                else
                {
                    ctx = SSLContext.getInstance(tlsVersion);
                }

                ctx.init(keyManagers, trustManagers, secureRandom);

                return ctx.getSocketFactory();
            }
        };
    }
}
