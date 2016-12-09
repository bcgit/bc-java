package org.bouncycastle.jsse.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

class ProvTrustManagerFactorySpi
    extends TrustManagerFactorySpi
{
    static final boolean hasExtendedTrustManager;

    static
    {
        Class clazz = null;
        try
        {
            clazz = ProvSSLServerSocket.class.getClassLoader().loadClass("javax.net.ssl.X509ExtendedTrustManager");
        }
        catch (Exception e)
        {
            clazz = null;
        }

        hasExtendedTrustManager = (clazz != null);
    }

    protected final Provider pkixProvider;

    protected X509TrustManager trustManager;

    public ProvTrustManagerFactorySpi(Provider pkixProvider)
    {
        this.pkixProvider = pkixProvider;
    }

    protected TrustManager[] engineGetTrustManagers()
    {
        return new TrustManager[]{ trustManager };
    }

    protected void engineInit(KeyStore ks)
        throws KeyStoreException
    {
        if (hasExtendedTrustManager)
        {
            trustManager = new ProvX509ExtendedTrustManager(new ProvX509TrustManager(pkixProvider, ks));
        }
        else
        {
            trustManager = new ProvX509TrustManager(pkixProvider, ks);
        }
    }

    protected void engineInit(ManagerFactoryParameters spec)
        throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException();
    }
}
