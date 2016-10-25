package org.bouncycastle.jsse.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

class ProvTrustManagerFactorySpi
    extends TrustManagerFactorySpi
{
    protected ProvX509TrustManager trustManager;

    protected TrustManager[] engineGetTrustManagers()
    {
        return new TrustManager[]{ trustManager };
    }

    protected void engineInit(KeyStore ks)
        throws KeyStoreException
    {
        trustManager = new ProvX509TrustManager(ks);
    }

    protected void engineInit(ManagerFactoryParameters spec)
        throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException();
    }
}
