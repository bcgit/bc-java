package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CombinedHash;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.NonceRandomGenerator;
import org.bouncycastle.tls.crypto.TlsAEADCipher;
import org.bouncycastle.tls.crypto.TlsAEADOperator;
import org.bouncycastle.tls.crypto.TlsBlockCipher;
import org.bouncycastle.tls.crypto.TlsBlockOperator;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsNullCipher;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamCipher;
import org.bouncycastle.tls.crypto.TlsStreamOperator;
import org.bouncycastle.tls.crypto.bc.Chacha20Poly1305;
import org.bouncycastle.util.Arrays;

public class JcaTlsCrypto
    extends AbstractTlsCrypto
{
    private final JcaJceHelper helper;

    JcaTlsCrypto(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    public JceTlsSecret adoptSecret(byte[] data)
    {
        return new JceTlsSecret(this, data);
    }

    public TlsCertificate createCertificate(byte[] encoding)
        throws IOException
    {
        return new JcaTlsCertificate(encoding, helper);
    }

    public TlsCipher createCipher(int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        try
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm._3DES_EDE_CBC:
                return createDESedeCipher(macAlgorithm);
            case EncryptionAlgorithm.AES_128_CBC:
                return createAESCipher(16, macAlgorithm);
            case EncryptionAlgorithm.AES_128_CCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(16, 16);
            case EncryptionAlgorithm.AES_128_CCM_8:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(16, 8);
            case EncryptionAlgorithm.AES_128_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_GCM(16, 16);
            case EncryptionAlgorithm.AES_128_OCB_TAGLEN96:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_OCB(16, 12);
            case EncryptionAlgorithm.AES_256_CBC:
                return createAESCipher(32, macAlgorithm);
            case EncryptionAlgorithm.AES_256_CCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(32, 16);
            case EncryptionAlgorithm.AES_256_CCM_8:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_CCM(32, 8);
            case EncryptionAlgorithm.AES_256_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_GCM(32, 16);
            case EncryptionAlgorithm.AES_256_OCB_TAGLEN96:
                // NOTE: Ignores macAlgorithm
                return createCipher_AES_OCB(32, 12);
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
                return createCamelliaCipher(16, macAlgorithm);
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_Camellia_GCM(16, 16);
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
                return createCamelliaCipher(32, macAlgorithm);
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
                // NOTE: Ignores macAlgorithm
                return createCipher_Camellia_GCM(32, 16);
            case EncryptionAlgorithm.CHACHA20_POLY1305:
                // NOTE: Ignores macAlgorithm
                return createChaCha20Poly1305();
            case EncryptionAlgorithm.NULL:
                return createNullCipher(macAlgorithm);
            case EncryptionAlgorithm.RC4_128:
                return createRC4Cipher(16, macAlgorithm);
            case EncryptionAlgorithm.SEED_CBC:
                return createSEEDCipher(macAlgorithm);
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    protected TlsBlockCipher createAESCipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(context, new BlockCipher("AES", "AES/CBC/NoPadding", true), new BlockCipher("AES", "AES/CBC/NoPadding", false),
            new JceTlsMac(context, createHMACDigest(macAlgorithm)), new JceTlsMac(context, createHMACDigest(macAlgorithm)), cipherKeySize, createHMACDigest(macAlgorithm).getDigestLength());
    }

    protected TlsBlockCipher createCamelliaCipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(context, new BlockCipher("Camellia", "Camellia/CBC/NoPadding", true), new BlockCipher("Camellia", "Camellia/CBC/NoPadding", false),
            new JceTlsMac(context, createHMACDigest(macAlgorithm)), new JceTlsMac(context, createHMACDigest(macAlgorithm)), cipherKeySize, createHMACDigest(macAlgorithm).getDigestLength());
    }

    protected TlsCipher createChaCha20Poly1305()
        throws IOException
    {
        return new Chacha20Poly1305(context);
    }

    protected TlsAEADCipher createCipher_AES_CCM(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(context, new AEADCipher("AES", "AES/CCM/NoPadding", true), new AEADCipher("AES", "AES/CCM/NoPadding", false),
            cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_GCM(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(context, new AEADCipher("AES", "AES/GCM/NoPadding", true), new AEADCipher("AES", "AES/GCM/NoPadding", false),
            cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_OCB(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(context, new AEADCipher("AES", "AES/OCB/NoPadding", true), new AEADCipher("AES", "AES/OCB/NoPadding", false),
            cipherKeySize, macSize, TlsAEADCipher.NONCE_RFC7905);
    }

    protected TlsAEADCipher createCipher_Camellia_GCM(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipher(context, new AEADCipher("Camellia", "Camellia/GCM/NoPadding", true), new AEADCipher("Camellia", "Camellia/GCM/NoPadding", false),
            cipherKeySize, macSize);
    }

    protected TlsBlockCipher createDESedeCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(context, new BlockCipher("DESede", "DESede/CBC/NoPadding", true), new BlockCipher("DESede", "DESede/CBC/NoPadding", false),
            new JceTlsMac(context, createHMACDigest(macAlgorithm)), new JceTlsMac(context, createHMACDigest(macAlgorithm)), 24, createHMACDigest(macAlgorithm).getDigestLength());
    }

    protected TlsNullCipher createNullCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsNullCipher(context, new JceTlsMac(context, createHMACDigest(macAlgorithm)), new JceTlsMac(context, createHMACDigest(macAlgorithm)), createHMACDigest(macAlgorithm).getDigestLength());
    }

    protected TlsStreamCipher createRC4Cipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsStreamCipher(context, new StreamCipher("RC4", "RC4", true), new StreamCipher("RC4", "RC4", false),
            new JceTlsMac(context, createHMACDigest(macAlgorithm)), new JceTlsMac(context, createHMACDigest(macAlgorithm)), cipherKeySize, createHMACDigest(macAlgorithm).getDigestLength(), false);
    }

    protected TlsBlockCipher createSEEDCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipher(context, new BlockCipher("SEED", "SEED/CBC/NoPadding", true), new BlockCipher("SEED", "SEED/CBC/NoPadding", false),
            new JceTlsMac(context, createHMACDigest(macAlgorithm)), new JceTlsMac(context, createHMACDigest(macAlgorithm)), 16, createHMACDigest(macAlgorithm).getDigestLength());
    }

    protected MessageDigest createHMACDigest(int macAlgorithm)
        throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            return null;
        case MACAlgorithm.hmac_md5:
            return createMessageDigest(HashAlgorithm.md5);
        case MACAlgorithm.hmac_sha1:
            return createMessageDigest(HashAlgorithm.sha1);
        case MACAlgorithm.hmac_sha256:
            return createMessageDigest(HashAlgorithm.sha256);
        case MACAlgorithm.hmac_sha384:
            return createMessageDigest(HashAlgorithm.sha384);
        case MACAlgorithm.hmac_sha512:
            return createMessageDigest(HashAlgorithm.sha512);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig)
    {
        return new JceTlsDHDomain(this, dhConfig);
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        return new JcaTlsECDomain(this, ecConfig);
    }

    public TlsSecret createSecret(byte[] data)
    {
        try
        {
            return adoptSecret(Arrays.clone(data));
        }
        finally
        {
            // TODO[tls-ops] Add this after checking all callers
//            if (data != null)
//            {
//                Arrays.fill(data, (byte)0);
//            }
        }
    }

    public TlsSecret generateRandomSecret(int length)
    {
        byte[] data = new byte[length];
        getContext().getSecureRandom().nextBytes(data);
        return adoptSecret(data);
    }

    public TlsHash createHash(short algorithm)
    {
        return new JcaTlsHash(createMessageDigest(algorithm));
    }

    public TlsContext getContext()
    {
        return context;
    }

    JcaJceHelper getHelper()
    {
        return helper;
    }


    public TlsHash createHash(final SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        if (signatureAndHashAlgorithm == null)
        {
            return new CombinedHash(getContext().getCrypto());
        }

        return new JcaTlsHash(createMessageDigest(signatureAndHashAlgorithm.getHash()));
    }

    public NonceRandomGenerator createNonceRandomGenerator()
    {
        // TODO: really need to find out the story on this one.
        final Digest d = new SHA256Digest();
        final DigestRandomGenerator gen = new DigestRandomGenerator(d);

        return new NonceRandomGenerator()
        {
            public void addSeedMaterial(byte[] seed)
            {
                gen.addSeedMaterial(seed);
            }

            public void addSeedMaterial(long seed)
            {
                gen.addSeedMaterial(seed);
            }

            public void addSeedMaterial(SecureRandom seedSource)
            {

                byte[] seed = new byte[d.getDigestSize()];
                seedSource.nextBytes(seed);
                addSeedMaterial(seed);
            }

            public void nextBytes(byte[] bytes)
            {
                gen.nextBytes(bytes);
            }

            public void nextBytes(byte[] bytes, int start, int len)
            {
                gen.nextBytes(bytes, start, len);
            }
        };
    }

    MessageDigest createMessageDigest(short hashAlgorithm)
    {
        String digestName;

        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            digestName = "MD5";
            break;
        case HashAlgorithm.sha1:
            digestName = "SHA-1";
            break;
        case HashAlgorithm.sha224:
            digestName = "SHA-224";
            break;
        case HashAlgorithm.sha256:
            digestName = "SHA-256";
            break;
        case HashAlgorithm.sha384:
            digestName = "SHA-384";
            break;
        case HashAlgorithm.sha512:
            digestName = "SHA-512";
            break;
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }

        try
        {
            return helper.createDigest(digestName);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException("unable to create message digest:" + e.getMessage(), e);
        }
    }

    private class JcaTlsHash
        implements TlsHash
    {
        private final MessageDigest digest;

        JcaTlsHash(MessageDigest digest)
        {
            this.digest = digest;
        }

        public void update(byte[] data, int offSet, int length)
        {
            digest.update(data, offSet, length);
        }

        public byte[] calculateHash()
        {
            return digest.digest();
        }

        public TlsHash cloneHash()
        {
            try
            {
                return new JcaTlsHash((MessageDigest)digest.clone());
            }
            catch (CloneNotSupportedException e)
            {
                throw new UnsupportedOperationException("unable to clone digest");
            }
        }

        public void reset()
        {
            digest.reset();
        }
    }

    private class BlockCipher
        implements TlsBlockOperator
    {
        private final int cipherMode;
        private final Cipher cipher;
        private final String baseAlgorithm;

        private SecretKey key;

        BlockCipher(String baseAlgorithm, String cipherName, boolean isEncrypting)
            throws GeneralSecurityException
        {
            this.cipher = helper.createCipher(cipherName);
            this.baseAlgorithm = baseAlgorithm;
            this.cipherMode = (isEncrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        }

        public void setKey(byte[] key)
        {
            this.key = new SecretKeySpec(key, baseAlgorithm);
        }

        public void init(byte[] iv)
        {
            try
            {
                cipher.init(cipherMode, key, new IvParameterSpec(iv));
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException(e);
            }
        }

        public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            try
            {
                return cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException(e);
            }
        }

        public int getBlockSize()
        {
            return cipher.getBlockSize();
        }
    }

    private class StreamCipher
        implements TlsStreamOperator
    {
        private final int cipherMode;
        private final Cipher cipher;
        private final String baseAlgorithm;

        private SecretKey key;

        StreamCipher(String baseAlgorithm, String cipherName, boolean isEncrypting)
            throws GeneralSecurityException
        {
            this.cipher = helper.createCipher(cipherName);
            this.baseAlgorithm = baseAlgorithm;
            this.cipherMode = (isEncrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        }

        public void setKey(byte[] key)
        {
            this.key = new SecretKeySpec(key, baseAlgorithm);
        }

        public void init(byte[] iv)
        {
            try
            {
                cipher.init(cipherMode, key, new IvParameterSpec(iv));
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException(e);
            }
        }

        public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            try
            {
                return cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException(e);
            }
        }
    }

    private class AEADCipher
        implements TlsAEADOperator
    {
        private final int cipherMode;
        private final Cipher cipher;
        private final String baseAlgorithm;

        private SecretKey key;

        AEADCipher(String baseAlgorithm, String cipherName, boolean isEncrypting)
            throws GeneralSecurityException
        {
            this.cipher = helper.createCipher(cipherName);
            this.baseAlgorithm = baseAlgorithm;
            this.cipherMode = (isEncrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        }

        public void setKey(byte[] key)
        {
            this.key = new SecretKeySpec(key, baseAlgorithm);
        }

        public void init(byte[] nonce, int macSize, byte[] additionalData)
        {
            try
            {
                cipher.init(cipherMode, key, new AEADParameterSpec(nonce, macSize * 8, additionalData));
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException(e);
            }
        }

        public int getOutputSize(int inputLength)
        {
            return cipher.getOutputSize(inputLength);
        }

        public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            try
            {
                return cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException(e);
            }
        }
    }
}
