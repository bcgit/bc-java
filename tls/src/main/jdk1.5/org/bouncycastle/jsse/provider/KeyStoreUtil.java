package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

abstract class KeyStoreUtil
{
    private static final Method getProtectionAlgorithm;

    static
    {
        getProtectionAlgorithm = ReflectionUtil.getMethod("java.security.KeyStore$PasswordProtection",
            "getProtectionAlgorithm");
    }

    static Key getKey(KeyStore keyStore, String alias, KeyStore.ProtectionParameter protectionParameter)
        throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if (null == protectionParameter)
        {
            throw new UnrecoverableKeyException("requested key requires a password");
        }

        if (protectionParameter instanceof KeyStore.PasswordProtection)
        {
            KeyStore.PasswordProtection passwordProtection = (KeyStore.PasswordProtection)protectionParameter;

            if (null != getProtectionAlgorithm)
            {
                if (null != ReflectionUtil.invokeGetter(passwordProtection, getProtectionAlgorithm))
                {
                    throw new KeyStoreException("unsupported password protection algorithm");
                }
            }

            return keyStore.getKey(alias, passwordProtection.getPassword());
        }

        throw new UnsupportedOperationException();
    }
}
