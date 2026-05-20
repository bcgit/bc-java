package org.bouncycastle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

/**
 * LoadStoreParameter to allow configuring of the PBKDF used to generate encryption keys for
 * use in the keystore.
 */
public class PKCS12LoadStoreParameter
    extends BCLoadStoreParameter
{
    public static class Builder
    {
        private final OutputStream out;
        private final InputStream in;
        private final KeyStore.ProtectionParameter protectionParameter;

        private boolean useISO8859d1ForDecryption = false;

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

        public Builder setUseISO8859d1ForDecryption(boolean enabled)
        {
            this.useISO8859d1ForDecryption = enabled;

            return this;
        }

        /**
         * Build and return a PKCS12LoadStoreParameter.
         *
         * @return a new PKCS12LoadStoreParameter.
         */
        public PKCS12LoadStoreParameter build()
        {
            return new PKCS12LoadStoreParameter(this);
        }
    }

    private final boolean useISO8859d1ForDecryption;

    private PKCS12LoadStoreParameter(Builder bldr)
    {
        super(bldr.in, bldr.out, bldr.protectionParameter);

        this.useISO8859d1ForDecryption = bldr.useISO8859d1ForDecryption;
    }

    public boolean useISO8859d1ForDecryption()
    {
        return useISO8859d1ForDecryption;
    }
}
