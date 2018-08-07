package org.bouncycastle.jcajce;

import java.io.OutputStream;
import java.security.KeyStore;

import org.bouncycastle.crypto.util.PBKDFConfig;

/**
 * LoadStoreParameter to allow configuring of the PBKDF used to generate encryption keys for
 * use in the keystore.
 * @deprecated This class does not support configuration on creation, use BCFKSLoadStoreParameter for best results.
 */
public class BCFKSStoreParameter
    implements KeyStore.LoadStoreParameter
{
    private final KeyStore.ProtectionParameter protectionParameter;
    private final PBKDFConfig storeConfig;

    private OutputStream out;

    public BCFKSStoreParameter(OutputStream out, PBKDFConfig storeConfig, char[] password)
    {
        this(out, storeConfig, new KeyStore.PasswordProtection(password));
    }

    public BCFKSStoreParameter(OutputStream out, PBKDFConfig storeConfig, KeyStore.ProtectionParameter protectionParameter)
    {
        this.out = out;
        this.storeConfig = storeConfig;
        this.protectionParameter = protectionParameter;
    }

    public KeyStore.ProtectionParameter getProtectionParameter()
    {
        return protectionParameter;
    }

    public OutputStream getOutputStream()
    {
        return out;
    }

    /**
     * Return the PBKDF used for generating the HMAC and store encryption keys.
     *
     * @return the PBKDF to use for deriving HMAC and store encryption keys.
     */
    public PBKDFConfig getStorePBKDFConfig()
    {
        return storeConfig;
    }
}
