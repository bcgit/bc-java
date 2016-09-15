package org.bouncycastle.jsse.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;

class ProvKeyManagerFactorySpi
    extends KeyManagerFactorySpi
{
    // at the moment we're only accepting X.509/PKCS#8 key material so there is only one key manager needed
    KeyManager keyManager;

    protected void engineInit(KeyStore keyStore, char[] passwd)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if (keyStore == null)
        {
            keyManager = new ProvX509KeyManager(Collections.<KeyStore.Builder>emptyList());
        }
        else
        {
            try
            {
                KeyStore.Builder builder = KeyStore.Builder.newInstance(keyStore, new KeyStore.PasswordProtection(passwd));
                keyManager = new ProvX509KeyManager(Collections.singletonList(builder));
            }
            catch (RuntimeException e)
            {
                throw new KeyStoreException("initialization failed", e);
            }
        }
    }

    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException
    {
        if (managerFactoryParameters instanceof KeyStoreBuilderParameters)
        {
            List<KeyStore.Builder> builders = ((KeyStoreBuilderParameters)managerFactoryParameters).getParameters();
            keyManager = new ProvX509KeyManager(builders);
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
