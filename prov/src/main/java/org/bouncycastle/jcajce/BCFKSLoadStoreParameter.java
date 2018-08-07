package org.bouncycastle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.crypto.util.PBKDFConfig;

/**
 * LoadStoreParameter to allow configuring of the PBKDF used to generate encryption keys for
 * use in the keystore.
 */
public class BCFKSLoadStoreParameter
    extends BCLoadStoreParameter
{

    public enum EncryptionAlgorithm
    {
        AES256_CCM,
        AES256_KWP
    }

    public enum MacAlgorithm
    {
        HmacSHA512,
        HmacSHA3_512
    }

    public static class Builder
    {
        private final OutputStream out;
        private final InputStream in;
        private final KeyStore.ProtectionParameter protectionParameter;

        private PBKDFConfig storeConfig = new PBKDF2Config.Builder()
                                                .withIterationCount(16384)
                                                .withSaltLength(64).withPRF(PBKDF2Config.PRF_SHA512).build();
        private EncryptionAlgorithm encAlg = EncryptionAlgorithm.AES256_CCM;
        private MacAlgorithm macAlg = MacAlgorithm.HmacSHA512;

        /**
         * Base constructor for creating a LoadStoreParameter for initializing a key store.
         */
        public Builder()
        {
            this((OutputStream)null, (KeyStore.ProtectionParameter)null);
        }

        /**
         * Base constructor for storing to an OutputStream using a password.
         *
         * @param out OutputStream to write KeyStore to.
         * @param password the password to use to protect the KeyStore.
         */
        public Builder(OutputStream out, char[] password)
        {
            this(out, new KeyStore.PasswordProtection(password));
        }

        /**
         * Base constructor for storing to an OutputStream using a protection parameter.
         *
         * @param out OutputStream to write KeyStore to.
         * @param protectionParameter the protection parameter to use to protect the KeyStore.
         */
        public Builder(OutputStream out, KeyStore.ProtectionParameter protectionParameter)
        {
            this.in = null;
            this.out = out;
            this.protectionParameter = protectionParameter;
        }

        /**
         * Base constructor for reading a KeyStore from an InputStream using a password.
         *
         * @param in InputStream to read the KeyStore from.
         * @param password the password used to protect the KeyStore.
         */
        public Builder(InputStream in, char[] password)
        {
            this(in, new KeyStore.PasswordProtection(password));
        }

        /**
         * Base constructor for reading a KeyStore from an InputStream using a password.
         *
         * @param in InputStream to read the KeyStore from.
         * @param protectionParameter  the protection parameter used to protect the KeyStore.
         */
        public Builder(InputStream in, KeyStore.ProtectionParameter protectionParameter)
        {
            this.in = in;
            this.out = null;
            this.protectionParameter = protectionParameter;
        }

        /**
         * Configure the PBKDF to use for protecting the KeyStore.
         *
         * @param storeConfig the PBKDF config to use for protecting the KeyStore.
         * @return the current Builder instance.
         */
        public Builder withStorePBKDFConfig(PBKDFConfig storeConfig)
        {
            this.storeConfig = storeConfig;
            return this;
        }

        /**
         * Configure the encryption algorithm to use for protecting the KeyStore and its keys.
         *
         * @param encAlg the PBKDF config to use for protecting the KeyStore and its keys.
         * @return the current Builder instance.
         */
        public Builder withStoreEncryptionAlgorithm(EncryptionAlgorithm encAlg)
        {
            this.encAlg = encAlg;
            return this;
        }

        /**
         * Configure the MAC algorithm to use for protecting the KeyStore.
         *
         * @param macAlg the PBKDF config to use for protecting the KeyStore.
         * @return the current Builder instance.
         */
        public Builder withStoreMacAlgorithm(MacAlgorithm macAlg)
        {
            this.macAlg = macAlg;
            return this;
        }

        /**
         * Build and return a BCFKSLoadStoreParameter.
         *
         * @return a new BCFKSLoadStoreParameter.
         */
        public BCFKSLoadStoreParameter build()
        {
            return new BCFKSLoadStoreParameter(in, out, storeConfig, protectionParameter, encAlg, macAlg);
        }
    }

    private final PBKDFConfig storeConfig;
    private final EncryptionAlgorithm encAlg;
    private final MacAlgorithm macAlg;

    private BCFKSLoadStoreParameter(InputStream in, OutputStream out, PBKDFConfig storeConfig, KeyStore.ProtectionParameter protectionParameter, EncryptionAlgorithm encAlg, MacAlgorithm macAlg)
    {
        super(in, out, protectionParameter);

        this.storeConfig = storeConfig;
        this.encAlg = encAlg;
        this.macAlg = macAlg;
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

    /**
     * Return encryption algorithm used to secure the store and its entries.
     *
     * @return the encryption algorithm to use.
     */
    public EncryptionAlgorithm getStoreEncryptionAlgorithm()
    {
        return encAlg;
    }

    /**
     * Return encryption algorithm used to secure the store and its entries.
     *
     * @return the encryption algorithm to use.
     */
    public MacAlgorithm getStoreMacAlgorithm()
    {
        return macAlg;
    }
}
