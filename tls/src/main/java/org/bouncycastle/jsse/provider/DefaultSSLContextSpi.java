package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

class DefaultSSLContextSpi extends ProvSSLContextSpi
{
    private static final Logger LOG = Logger.getLogger(DefaultSSLContextSpi.class.getName());

    private static Exception avoidCapturingException(Exception e)
    {
        // NOTE: Avoid capturing arbitrary exception into static field
        return new KeyManagementException(e.getMessage());
    }

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
                    LOG.log(Level.WARNING, "Failed to load default SSLContext", e);
                    ex = avoidCapturingException(e);
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
            KeyManager[] kms = null;
            TrustManager[] tms = null;

            try
            {
                tms = ProvSSLContextSpi.getDefaultTrustManagers();
            }
            catch (Exception e)
            {
                LOG.log(Level.WARNING, "Failed to load default trust managers", e);
                ex = e;
            }

            if (null == ex)
            {
                try
                {
                    kms = ProvSSLContextSpi.getDefaultKeyManagers();
                }
                catch (Exception e)
                {
                    LOG.log(Level.WARNING, "Failed to load default key managers", e);
                    ex = e;
                }
            }

            if (null != ex)
            {
                ex = avoidCapturingException(ex);
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
