package org.bouncycastle.jsse.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

class ProvTrustManagerFactory
    extends TrustManagerFactorySpi
{
    private ProvX509TrustManager trustManager;

    protected void engineInit(KeyStore trustStore)
        throws KeyStoreException
    {
        trustManager = new ProvX509TrustManager(trustStore);
    }

    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException
    {

    }

    protected TrustManager[] engineGetTrustManagers()
    {
        return new TrustManager[] { trustManager };
    }
}
