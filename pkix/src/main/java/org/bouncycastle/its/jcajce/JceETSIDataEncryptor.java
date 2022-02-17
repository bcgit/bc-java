package org.bouncycastle.its.jcajce;

import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.its.operator.ETSIDataEncryptor;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

public class JceETSIDataEncryptor
    implements ETSIDataEncryptor
{
    private final SecureRandom random;
    private final JcaJceHelper helper;

    private byte[] nonce;
    private byte[] key;

    private JceETSIDataEncryptor(SecureRandom random, JcaJceHelper helper)
    {
        this.random = random;
        this.helper = helper;
    }

    public byte[] encrypt(byte[] content)
    {
        key = new byte[16];
        random.nextBytes(key);

        nonce = new byte[12];
        random.nextBytes(nonce);

        try
        {
            SecretKey k = new SecretKeySpec(key, "AES");
            Cipher ccm = helper.createCipher("CCM");
            ccm.init(Cipher.ENCRYPT_MODE, k, ClassUtil.getGCMSpec(nonce, 128));
            return ccm.doFinal(content);
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public byte[] getKey()
    {
        return key;
    }

    public byte[] getNonce()
    {
        return nonce;
    }

    public static class Builder
    {
        private SecureRandom random;
        private JcaJceHelper helper = new DefaultJcaJceHelper();

        public Builder()
        {
        }

        public Builder setRandom(SecureRandom random)
        {
            this.random = random;
            return this;
        }

        /**
         * Sets the JCE provider to source cryptographic primitives from.
         *
         * @param provider the JCE provider to use.
         * @return the current builder.
         */
        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);

            return this;
        }

        /**
         * Sets the JCE provider to source cryptographic primitives from.
         *
         * @param providerName the name of the JCE provider to use.
         * @return the current builder.
         */
        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);

            return this;
        }

        public JceETSIDataEncryptor build()
        {
            if (random == null)
            {
                random = new SecureRandom();
            }
            return new JceETSIDataEncryptor(random, helper);
        }
    }
}
