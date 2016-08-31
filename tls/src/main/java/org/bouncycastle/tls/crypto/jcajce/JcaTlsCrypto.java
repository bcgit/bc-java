package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AbstractTlsCrypto;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CombinedHash;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.ChaCha20Poly1305CipherSuite;
import org.bouncycastle.tls.crypto.TlsAEADCipher;
import org.bouncycastle.tls.crypto.TlsAEADCipherSuite;
import org.bouncycastle.tls.crypto.TlsBlockCipher;
import org.bouncycastle.tls.crypto.TlsBlockCipherSuite;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipherSuite;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsMAC;
import org.bouncycastle.tls.crypto.TlsNullCipherSuite;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamCipher;
import org.bouncycastle.tls.crypto.TlsStreamCipherSuite;
import org.bouncycastle.util.Arrays;

public class JcaTlsCrypto
    extends AbstractTlsCrypto
{
    private final JcaJceHelper helper;
    private final SecureRandom nonceEntropySource;

    protected JcaTlsCrypto(JcaJceHelper helper, SecureRandom entropySource, SecureRandom nonceEntropySource)
    {
        super(entropySource);

        this.helper = helper;
        this.nonceEntropySource = nonceEntropySource;
    }

    public JceTlsSecret adoptSecret(byte[] data)
    {
        return new JceTlsSecret(this, data);
    }

    public byte[] createNonce(int size)
    {
        byte[] nonce = new byte[size];

        nonceEntropySource.nextBytes(nonce);

        return nonce;
    }

    public TlsCertificate createCertificate(byte[] encoding)
        throws IOException
    {
        return new JcaTlsCertificate(encoding, helper);
    }

    public TlsCipherSuite createCipher(int encryptionAlgorithm, int macAlgorithm)
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

    /**
     * If you want to create your own versions of the AEAD ciphers required, override this method.
     *
     * @param cipherName the full name of the cipher (algorithm/mode/padding)
     * @param algorithm the base algorithm name
     * @param keySize keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return an AEAD cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsAEADCipher createAEADCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceAEADCipher(helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    /**
     * If you want to create your own versions of the block ciphers required, override this method.
     *
     * @param cipherName the full name of the cipher (algorithm/mode/padding)
     * @param algorithm the base algorithm name
     * @param keySize keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return a block cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsBlockCipher createBlockCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceBlockCipher(helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    /**
     * If you want to create your own versions of the block ciphers for < TLS 1.1, override this method.
     *
     * @param cipherName the full name of the cipher (algorithm/mode/padding)
     * @param algorithm the base algorithm name
     * @param keySize keySize (in bytes) for the cipher key.
     * @param isEncrypting true if the cipher is for encryption, false otherwise.
     * @return a block cipher.
     * @throws GeneralSecurityException in case of failure.
     */
    protected TlsBlockCipher createBlockCipherWithImplicitIv(String cipherName, String algorithm, int keySize, boolean isEncrypting)
        throws GeneralSecurityException
    {
        return new JceBlockCipherWithImplictIv(helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    private TlsBlockCipherSuite createAESCipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipherSuite(context, createBlockOperator("AES/CBC/NoPadding", "AES", true, cipherKeySize), createBlockOperator("AES/CBC/NoPadding", "AES", false, cipherKeySize),
                createMac(macAlgorithm), createMac(macAlgorithm), cipherKeySize);
    }

    private TlsBlockCipherSuite createCamelliaCipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipherSuite(context, createBlockOperator("Camellia/CBC/NoPadding", "Camellia", true, cipherKeySize), createBlockOperator("Camellia/CBC/NoPadding", "Camellia", false, cipherKeySize),
            createMac(macAlgorithm), createMac(macAlgorithm), cipherKeySize);
    }

    private TlsBlockCipherSuite createDESedeCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipherSuite(context, createBlockOperator("DESede/CBC/NoPadding", "DESede", true, 24), createBlockOperator("DESede/CBC/NoPadding", "DESede", false, 24),
            createMac(macAlgorithm), createMac(macAlgorithm), 24);
    }

    private TlsBlockCipherSuite createSEEDCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsBlockCipherSuite(context, createBlockOperator("SEED/CBC/NoPadding", "SEED", true, 16), createBlockOperator("SEED/CBC/NoPadding", "SEED", false, 16),
            createMac(macAlgorithm), createMac(macAlgorithm), 16);
    }

    private TlsBlockCipher createBlockOperator(String cipherName, String algorithm, boolean forEncryption, int keySize)
        throws GeneralSecurityException
    {
        if (TlsUtils.isTLSv11(context))
        {
            return createBlockCipher(cipherName, algorithm, keySize, forEncryption);
        }
        else
        {
            return createBlockCipherWithImplicitIv(cipherName, algorithm, keySize, forEncryption);
        }
    }

    private TlsHMAC createMac(int macAlgorithm)
        throws GeneralSecurityException, IOException
    {
        if (TlsUtils.isSSL(context))
        {
            return createSSL3HMAC(macAlgorithm);
        }
        else
        {
            return createHMAC(macAlgorithm);
        }
    }

    protected TlsCipherSuite createChaCha20Poly1305()
        throws IOException, GeneralSecurityException
    {
        return new ChaCha20Poly1305CipherSuite(context, new StreamCipher("ChaCha7539", "ChaCha7539", true), new StreamCipher("ChaCha7539", "ChaCha7539", false),
                new TlsMac("Poly1305"), new TlsMac("Poly1305"));
    }

    private TlsAEADCipherSuite createCipher_AES_CCM(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipherSuite(context, createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, true), createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    private TlsAEADCipherSuite createCipher_AES_GCM(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipherSuite(context, createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, true), createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    private TlsAEADCipherSuite createCipher_AES_OCB(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipherSuite(context, createAEADCipher("AES/OCB/NoPadding", "AES", cipherKeySize, true), createAEADCipher("AES/OCB/NoPadding", "AES", cipherKeySize, false),
            cipherKeySize, macSize, TlsAEADCipherSuite.NONCE_RFC7905);
    }

    private TlsAEADCipherSuite createCipher_Camellia_GCM(int cipherKeySize, int macSize)
        throws IOException, GeneralSecurityException
    {
        return new TlsAEADCipherSuite(context, createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, true), createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, false),
            cipherKeySize, macSize);
    }

    protected TlsNullCipherSuite createNullCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsNullCipherSuite(context, createMac(macAlgorithm), createMac(macAlgorithm));
    }

    protected TlsStreamCipherSuite createRC4Cipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new TlsStreamCipherSuite(context, new StreamCipher("RC4", "RC4", true), new StreamCipher("RC4", "RC4", false),
            createMac(macAlgorithm), createMac(macAlgorithm), cipherKeySize, false);
    }

    public TlsHMAC createHMAC(int macAlgorithm)
        throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            return null;
        case MACAlgorithm.hmac_md5:
            return new TlsHMac("HmacMD5", 64);
        case MACAlgorithm.hmac_sha1:
            return new TlsHMac("HmacSHA1", 64);
        case MACAlgorithm.hmac_sha256:
            return new TlsHMac("HmacSHA256", 64);
        case MACAlgorithm.hmac_sha384:
            return new TlsHMac("HmacSHA384", 128);
        case MACAlgorithm.hmac_sha512:
            return new TlsHMac("HmacSHA512", 128);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsHMAC createSSL3HMAC(int macAlgorithm)
        throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            return null;
        case MACAlgorithm.hmac_md5:
            return new SSL3Mac(createMessageDigest(HashAlgorithm.md5), 64);
        case MACAlgorithm.hmac_sha1:
            return new SSL3Mac(createMessageDigest(HashAlgorithm.sha1), 64);
        case MACAlgorithm.hmac_sha256:
            return new SSL3Mac(createMessageDigest(HashAlgorithm.sha256), 64);
        case MACAlgorithm.hmac_sha384:
            return new SSL3Mac(createMessageDigest(HashAlgorithm.sha384), 128);
        case MACAlgorithm.hmac_sha512:
            return new SSL3Mac(createMessageDigest(HashAlgorithm.sha512), 128);
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
        getSecureRandom().nextBytes(data);
        return adoptSecret(data);
    }

    public TlsHash createHash(short algorithm)
    {
        return new JcaTlsHash(createMessageDigest(algorithm));
    }


    JcaJceHelper getHelper()
    {
        return helper;
    }


    public TlsHash createHash(final SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        if (signatureAndHashAlgorithm == null)
        {
            return new CombinedHash(this);
        }

        return new JcaTlsHash(createMessageDigest(signatureAndHashAlgorithm.getHash()));
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

    private class StreamCipher
        implements TlsStreamCipher
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
                int len = cipher.doFinal(input, inputOffset, inputLength, output, outputOffset);

                return len;
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException(e);
            }
        }
    }

    private class TlsMac
        implements TlsMAC
    {
        private final String algorithm;

        private Mac hmac;

        TlsMac(String algorithm)
        {
            this.algorithm = algorithm;
            try
            {
                this.hmac = helper.createMac(algorithm);
            }
            catch (GeneralSecurityException e)
            {                     e.printStackTrace(System.err);
                throw new IllegalStateException("cannot create HMAC: " + e.getMessage(), e);
            }
        }

        public void setKey(byte[] key)
        {
            try
            {
                hmac.init(new SecretKeySpec(key, algorithm));
            }
            catch (InvalidKeyException e)
            {
                e.printStackTrace();
            }
        }

        public void update(byte[] input, int inOff, int length)
        {
            hmac.update(input, inOff, length);
        }

        public byte[] calculateMAC()
        {
            return hmac.doFinal();
        }

        public int getMacLength()
        {
            return hmac.getMacLength();
        }

        public void reset()
        {
            hmac.reset();
        }
    }

    private class TlsHMac
        implements TlsHMAC
    {
        private final String algorithm;
        private final int internalBlockSize;

        private Mac hmac;

        TlsHMac(String algorithm, int internalBlockSize)
        {
            this.algorithm = algorithm;
            this.internalBlockSize = internalBlockSize;
            try
            {
                this.hmac = helper.createMac(algorithm);
            }
            catch (GeneralSecurityException e)
            {                     e.printStackTrace(System.err);
                throw new IllegalStateException("cannot create HMAC: " + e.getMessage(), e);
            }
        }

        public void setKey(byte[] key)
        {
            try
            {
                hmac.init(new SecretKeySpec(key, algorithm));
            }
            catch (InvalidKeyException e)
            {
                e.printStackTrace();
            }
        }

        public void update(byte[] input, int inOff, int length)
        {
            hmac.update(input, inOff, length);
        }

        public byte[] calculateMAC()
        {
            return hmac.doFinal();
        }

        public int getInternalBlockSize()
        {
            return internalBlockSize;
        }

        public int getMacLength()
        {
            return hmac.getMacLength();
        }

        public void reset()
        {
            hmac.reset();
        }
    }

    /**
     * HMAC implementation based on original internet draft for HMAC (RFC 2104)
     * <p>
     * The difference is that padding is concatenated versus XORed with the key
     * <p>
     * H(K + opad, H(K + ipad, text))
     */
    private static class SSL3Mac
        implements TlsHMAC
    {
        private static final byte IPAD_BYTE = (byte)0x36;
        private static final byte OPAD_BYTE = (byte)0x5C;

        private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
        private static final byte[] OPAD = genPad(OPAD_BYTE, 48);

        private MessageDigest digest;
        private final int internalBlockSize;
        private int padLength;

        private byte[] secret;

        /**
         * Base constructor for one of the standard digest algorithms that the byteLength of
         * the algorithm is know for. Behaviour is undefined for digests other than MD5 or SHA1.
         *
         * @param digest the digest.
         */
        public SSL3Mac(MessageDigest digest, int internalBlockSize)
        {
            this.digest = digest;
            this.internalBlockSize = internalBlockSize;

            if (digest.getDigestLength() == 20)
            {
                this.padLength = 40;
            }
            else
            {
                this.padLength = 48;
            }
        }

        public void setKey(byte[] key)
        {
            this.secret = key;

            reset();
        }

        public void update(byte[] in, int inOff, int len)
        {
            digest.update(in, inOff, len);
        }

        public byte[] calculateMAC()
        {
            byte[] tmp = digest.digest();

            digest.update(secret, 0, secret.length);
            digest.update(OPAD, 0, padLength);
            digest.update(tmp, 0, tmp.length);

            byte[] rv = digest.digest();

            reset();

            return rv;
        }

        public int getInternalBlockSize()
        {
            return internalBlockSize;
        }

        public int getMacLength()
        {
            return digest.getDigestLength();
        }

        /**
         * Reset the mac generator.
         */
        public void reset()
        {
            digest.reset();
            digest.update(secret, 0, secret.length);
            digest.update(IPAD, 0, padLength);
        }

        private static byte[] genPad(byte b, int count)
        {
            byte[] padding = new byte[count];
            Arrays.fill(padding, b);
            return padding;
        }
    }
}
