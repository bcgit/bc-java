package org.bouncycastle.jsse.provider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.util.List;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;

class ProvKeyManagerFactorySpi
    extends KeyManagerFactorySpi
{
    private static final Logger LOG = Logger.getLogger(ProvKeyManagerFactorySpi.class.getName());

    static KeyStoreConfig getDefaultKeyStore() throws Exception
    {
        String defaultType = KeyStore.getDefaultType();

        String ksPath = null;
        char[] ksPassword = null;

        String ksPathProp = PropertyUtils.getSystemProperty("javax.net.ssl.keyStore");
        if ("NONE".equals(ksPathProp))
        {
            // Do not try to load any file
        }
        else if (null != ksPathProp)
        {
            if (new File(ksPathProp).exists())
            {
                ksPath = ksPathProp;
            }
        }

        KeyStore ks = createKeyStore(defaultType);

        String ksPasswordProp = PropertyUtils.getSystemProperty("javax.net.ssl.keyStorePassword");
        if (null != ksPasswordProp)
        {
            ksPassword = ksPasswordProp.toCharArray();
        }

        InputStream ksInput = null;
        try
        {
            if (null == ksPath)
            {
                LOG.finest("Initializing empty key store");
            }
            else
            {
                LOG.finest("Initializing with key store at path: " + ksPath);
                ksInput = new BufferedInputStream(new FileInputStream(ksPath));
            }

            ks.load(ksInput, ksPassword);
        }
        finally
        {
            if (null != ksInput)
            {
                ksInput.close();
            }
        }

        return new KeyStoreConfig(ks, ksPassword);
    }

    // at the moment we're only accepting X.509/PKCS#8 key material so there is only one key manager needed
    protected X509ExtendedKeyManager x509KeyManager = null;

    ProvKeyManagerFactorySpi()
    {
    }

    @Override
    protected KeyManager[] engineGetKeyManagers()
    {
        if (null == x509KeyManager)
        {
            throw new IllegalStateException("KeyManagerFactory not initialized");
        }

        return new KeyManager[]{ x509KeyManager };
    }

    @Override
    protected void engineInit(KeyStore ks, char[] ksPassword)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        // NOTE: When key store is null, we do not try to load defaults

        this.x509KeyManager = new ProvX509KeyManagerSimple(ks, ksPassword);
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException
    {
        if (managerFactoryParameters instanceof KeyStoreBuilderParameters)
        {
            List<KeyStore.Builder> builders = ((KeyStoreBuilderParameters)managerFactoryParameters).getParameters();
            this.x509KeyManager = new ProvX509KeyManager(builders);
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Parameters must be instance of KeyStoreBuilderParameters");
        }
    }

    private static KeyStore createKeyStore(String defaultType)
        throws NoSuchProviderException, KeyStoreException
    {
        String ksType = getKeyStoreType(defaultType);
        String ksProv = PropertyUtils.getSystemProperty("javax.net.ssl.keyStoreProvider");
        return (null == ksProv || ksProv.length() < 1)
            ?   KeyStore.getInstance(ksType)
            :   KeyStore.getInstance(ksType, ksProv);
    }

    private static String getKeyStoreType(String defaultType)
    {
        String ksType = PropertyUtils.getSystemProperty("javax.net.ssl.keyStoreType");
        return (null == ksType) ? defaultType : ksType;
    }
}
