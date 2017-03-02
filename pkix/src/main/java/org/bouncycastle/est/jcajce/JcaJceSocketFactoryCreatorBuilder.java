package org.bouncycastle.est.jcajce;


import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

public class JcaJceSocketFactoryCreatorBuilder
{
    protected String tlsVersion = "TLS";
    protected String tlsProvider;
    protected KeyManager[] keyManagers;
    protected X509TrustManager[] trustManagers;

    public JcaJceSocketFactoryCreatorBuilder(X509TrustManager trustManager)
    {
        if (trustManager == null)
        {
            throw new NullPointerException("Trust managers can not be null");
        }
        this.trustManagers = new X509TrustManager[]{ trustManager };
    }

    public JcaJceSocketFactoryCreatorBuilder(X509TrustManager[] trustManagers)
    {
        if (trustManagers == null)
        {
            throw new NullPointerException("Trust managers can not be null");
        }
        this.trustManagers = trustManagers;
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

    public JcaJceSocketFactoryCreatorBuilder withKeyManager(KeyManager keyManager)
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

    public JcaJceSocketFactoryCreatorBuilder withKeyManagers(KeyManager[] keyManagers)
    {
        this.keyManagers = keyManagers;

        return this;
    }

    public SocketFactoryCreator build()
    {
        if (trustManagers == null)
        {

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

                ctx.init(keyManagers, trustManagers, new SecureRandom());

                return ctx.getSocketFactory();
            }
        };
    }
}
