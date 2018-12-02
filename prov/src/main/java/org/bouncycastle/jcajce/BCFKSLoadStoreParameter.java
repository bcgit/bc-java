package org.bouncycastle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

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

    public enum SignatureAlgorithm
    {
        SHA512withDSA,
        SHA3_512withDSA,
        SHA512withECDSA,
        SHA3_512withECDSA,
        SHA512withRSA,
        SHA3_512withRSA
    }

    public interface CertChainValidator
    {
        /**
         * Return true if the passed in chain is valid, false otherwise.
         *
         * @param chain the certChain we know about, the end-entity is at position 0.
         * @return true if valid, false otherwise.
         */
         boolean isValid(X509Certificate[] chain);
    }

    public static class Builder
    {
        private final OutputStream out;
        private final InputStream in;
        private final KeyStore.ProtectionParameter protectionParameter;
        private final Key sigKey;

        private PBKDFConfig storeConfig = new PBKDF2Config.Builder()
                                                .withIterationCount(16384)
                                                .withSaltLength(64).withPRF(PBKDF2Config.PRF_SHA512).build();
        private EncryptionAlgorithm encAlg = EncryptionAlgorithm.AES256_CCM;
        private MacAlgorithm macAlg = MacAlgorithm.HmacSHA512;
        private SignatureAlgorithm sigAlg = SignatureAlgorithm.SHA512withECDSA;
        private X509Certificate[] certs = null;
        private CertChainValidator validator;


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
            this.sigKey = null;
        }

        /**
         * Base constructor for storing to an OutputStream using a protection parameter.
         *
         * @param out OutputStream to write KeyStore to.
         * @param sigKey the key used to protect the integrity of the key store.
         */
        public Builder(OutputStream out, PrivateKey sigKey)
        {
            this.in = null;
            this.out = out;
            this.protectionParameter = null;
            this.sigKey = sigKey;
        }

        /**
         * Base constructor for reading a KeyStore from an InputStream using a public key for validation.
         *
         * @param in InputStream to load KeyStore to.
         * @param sigKey the public key parameter to used to verify the KeyStore.
         */
        public Builder(InputStream in, PublicKey sigKey)
        {
            this.in = in;
            this.out = null;
            this.protectionParameter = null;
            this.sigKey = sigKey;
        }

        /**
         * Base constructor for reading a KeyStore from an InputStream using validation based on
         * encapsulated certificates in the KeyStore data.
         *
         * @param in InputStream to load KeyStore to.
         * @param validator the certificate chain validator to check the signing certificates.
         */
        public Builder(InputStream in, CertChainValidator validator)
        {
            this.in = in;
            this.out = null;
            this.protectionParameter = null;
            this.validator = validator;
            this.sigKey = null;
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
            this.sigKey = null;
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
         * Add a valid certificate chain where certs[0] is the end-entity matching the
         * private key we are using to sign the key store.
         *
         * @param certs an array of X509 certificates.
         * @return the current Builder instance.
         */
        public Builder withCertificates(X509Certificate[] certs)
        {
            X509Certificate[] tmp = new X509Certificate[certs.length];
            System.arraycopy(certs, 0, tmp, 0, tmp.length);
            this.certs = tmp;

            return this;
        }

        /**
         * Configure the signature algorithm to use for protecting the KeyStore.
         *
         * @param sigAlg the signature config to use for protecting the KeyStore.
         * @return the current Builder instance.
         */
        public Builder withStoreSignatureAlgorithm(SignatureAlgorithm sigAlg)
        {
            this.sigAlg = sigAlg;

            return this;
        }

        /**
         * Build and return a BCFKSLoadStoreParameter.
         *
         * @return a new BCFKSLoadStoreParameter.
         */
        public BCFKSLoadStoreParameter build()
        {
            return new BCFKSLoadStoreParameter(this);
        }
    }

    private final PBKDFConfig storeConfig;
    private final EncryptionAlgorithm encAlg;
    private final MacAlgorithm macAlg;
    private final SignatureAlgorithm sigAlg;
    private final Key sigKey;
    private final X509Certificate[] certificates;
    private final CertChainValidator validator;

    private BCFKSLoadStoreParameter(Builder bldr)
    {
        super(bldr.in, bldr.out, bldr.protectionParameter);

        this.storeConfig = bldr.storeConfig;
        this.encAlg = bldr.encAlg;
        this.macAlg = bldr.macAlg;
        this.sigAlg = bldr.sigAlg;
        this.sigKey = bldr.sigKey;
        this.certificates = bldr.certs;
        this.validator = bldr.validator;
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
     * Return mac algorithm used to protect the integrity of the store and its contents.
     *
     * @return the mac algorithm to use.
     */
    public MacAlgorithm getStoreMacAlgorithm()
    {
        return macAlg;
    }

    /**
     * Return signature algorithm used to protect the integrity of the store and its contents.
     *
     * @return the signature algorithm to use.
     */
    public SignatureAlgorithm getStoreSignatureAlgorithm()
    {
        return sigAlg;
    }

    public Key getStoreSignatureKey()
    {
        return sigKey;
    }

    public X509Certificate[] getStoreCertificates()
    {
        return certificates;
    }

    public CertChainValidator getCertChainValidator()
    {
        return validator;
    }
}
