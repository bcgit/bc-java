package org.bouncycastle.jsse.provider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;

class ProvKeyManagerFactorySpi
    extends KeyManagerFactorySpi
{
    private static Logger LOG = Logger.getLogger(ProvKeyManagerFactorySpi.class.getName());

    // at the moment we're only accepting X.509/PKCS#8 key material so there is only one key manager needed
    KeyManager keyManager;

    protected void engineInit(KeyStore ks, char[] ksPassword)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        try
        {
            if (ks == null)
            {
                ksPassword = null;

                String ksType = PropertyUtils.getSystemProperty("javax.net.ssl.keyStoreType");
                if (ksType == null)
                {
                    ksType = KeyStore.getDefaultType();
                }

                String ksProv = PropertyUtils.getSystemProperty("javax.net.ssl.keyStoreProvider");
                ks = (ksProv == null || ksProv.length() < 1)
                    ?   KeyStore.getInstance(ksType)
                    :   KeyStore.getInstance(ksType, ksProv);

                String ksPath = null;

                String ksPathProp = PropertyUtils.getSystemProperty("javax.net.ssl.keyStore");
                if (ksPathProp != null)
                {
                    if (new File(ksPathProp).exists())
                    {
                        ksPath = ksPathProp;

                        String ksPasswordProp = PropertyUtils.getSystemProperty("javax.net.ssl.keyStorePassword");
                        if (ksPasswordProp != null)
                        {
                            ksPassword = ksPasswordProp.toCharArray();
                        }
                    }
                }

                if (ksPath == null)
                {
                    ks.load(null, null);
                    LOG.info("Initialized with empty key store");
                }
                else
                {
                    InputStream tsInput = new BufferedInputStream(new FileInputStream(ksPath));
                    ks.load(tsInput, ksPassword);
                    tsInput.close();
                    LOG.info("Initialized with key store at path: " + ksPath);
                }
            }

            keyManager = new ProvX509KeyManagerSimple(ks, ksPassword);
        }
        catch (Exception e)
        {
            throw new KeyStoreException("initialization failed", e);
        }
    }

    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException
    {
        if (managerFactoryParameters instanceof KeyStoreBuilderParameters)
        {
            List<KeyStore.Builder> builders = ((KeyStoreBuilderParameters)managerFactoryParameters).getParameters();
            keyManager = new ProvX509KeyManager(builders);
            return;
        }

        throw new InvalidAlgorithmParameterException("Parameters must be instance of KeyStoreBuilderParameters");
    }

    protected KeyManager[] engineGetKeyManagers()
    {
        if (keyManager != null)
        {
            return new KeyManager[] { keyManager };
        }
        throw new IllegalStateException("KeyManagerFactory not initialized");
    }
}
