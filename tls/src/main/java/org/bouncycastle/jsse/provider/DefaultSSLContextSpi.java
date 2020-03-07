package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

class DefaultSSLContextSpi extends ProvSSLContextSpi
{
    private static class LazyInstance
    {
        private static final Exception initException;
        private static final DefaultSSLContextSpi instance;

        static
        {
            Exception ex = LazyManagers.initException;
            DefaultSSLContextSpi i = null;

            if (null == ex)
            {
                try
                {
                    i = new DefaultSSLContextSpi(false, new JcaTlsCryptoProvider()); 
                }
                catch (Exception e)
                {
                    ex = e;
                    i = null;
                }
            }

            initException = ex;
            instance = i;
        }
    }

    private static class LazyManagers
    {
        private static final Exception initException;
        private static final KeyManager[] keyManagers;
        private static final TrustManager[] trustManagers;

        static
        {
            Exception ex = null;
            KeyManager[] kms;
            TrustManager[] tms;

            try
            {
                kms = ProvSSLContextSpi.getDefaultKeyManagers();
                tms = ProvSSLContextSpi.getDefaultTrustManagers();
            }
            catch (Exception e)
            {
                ex = e;
                kms = null;
                tms = null;
            }

            initException = ex;
            keyManagers = kms;
            trustManagers = tms;
        }
    }

    static ProvSSLContextSpi getDefaultInstance() throws Exception
    {
        if (null != LazyInstance.initException)
        {
            throw LazyInstance.initException;
        }

        return LazyInstance.instance;
    }

    DefaultSSLContextSpi(boolean isInFipsMode, JcaTlsCryptoProvider cryptoProvider) throws KeyManagementException
    {
        super(isInFipsMode, cryptoProvider, null);

        if (null != LazyManagers.initException)
        {
            throw new KeyManagementException("Default key/trust managers unavailable", LazyManagers.initException);
        }

        super.engineInit(LazyManagers.keyManagers, LazyManagers.trustManagers, null);
    }

    @Override
    protected void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr)
        throws KeyManagementException
    {
        throw new KeyManagementException("Default SSLContext is initialized automatically");
    }
}
