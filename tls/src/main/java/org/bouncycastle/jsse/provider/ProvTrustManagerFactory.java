package org.bouncycastle.jsse.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;

class ProvTrustManagerFactory
    extends TrustManagerFactorySpi
{
    protected void engineInit(KeyStore keyStore)
        throws KeyStoreException
    {

    }

    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException
    {

    }

    protected TrustManager[] engineGetTrustManagers()
    {
        return new TrustManager[0];
    }
}
