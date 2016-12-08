package org.bouncycastle.jsse.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

class ProvTrustManagerFactorySpi
    extends TrustManagerFactorySpi
{
    protected final Provider pkixProvider;

    protected ProvX509TrustManager trustManager;

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
        trustManager = new ProvX509TrustManager(pkixProvider, ks);
    }

    protected void engineInit(ManagerFactoryParameters spec)
        throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException();
    }
}
