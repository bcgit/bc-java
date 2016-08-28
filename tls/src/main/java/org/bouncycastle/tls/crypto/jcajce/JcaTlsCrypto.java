package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
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
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.bc.Chacha20Poly1305;
import org.bouncycastle.util.Arrays;

public class JcaTlsCrypto extends AbstractTlsCrypto
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

    public TlsCipher createCipher(int encryptionAlgorithm, int macAlgorithm) throws IOException
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

    protected JceTlsBlockCipher createAESCipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new JceTlsBlockCipher(context, "AES", createAESBlockCipher(), createAESBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize);
    }

    protected JceTlsBlockCipher createCamelliaCipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new JceTlsBlockCipher(context, "Camellia", createCamelliaBlockCipher(), createCamelliaBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createChaCha20Poly1305()
        throws IOException
    {
        return new Chacha20Poly1305(context);
    }

    protected JceTlsAEADCipher createCipher_AES_CCM(int cipherKeySize, int macSize)
        throws IOException
    {
        return new JceTlsAEADCipher(context, createAEADBlockCipher_AES_CCM(), createAEADBlockCipher_AES_CCM(),
            cipherKeySize, macSize);
    }

    protected JceTlsAEADCipher createCipher_AES_GCM(int cipherKeySize, int macSize)
        throws IOException
    {
        return new JceTlsAEADCipher(context, createAEADBlockCipher_AES_GCM(), createAEADBlockCipher_AES_GCM(),
            cipherKeySize, macSize);
    }

    protected JceTlsAEADCipher createCipher_AES_OCB(int cipherKeySize, int macSize)
        throws IOException
    {
        return new JceTlsAEADCipher(context, createAEADBlockCipher_AES_OCB(), createAEADBlockCipher_AES_OCB(),
            cipherKeySize, macSize, JceTlsAEADCipher.NONCE_RFC7905);
    }

    protected JceTlsAEADCipher createCipher_Camellia_GCM(int cipherKeySize, int macSize)
        throws IOException
    {
        return new JceTlsAEADCipher(context, createAEADBlockCipher_Camellia_GCM(), createAEADBlockCipher_Camellia_GCM(),
            cipherKeySize, macSize);
    }

    protected JceTlsBlockCipher createDESedeCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new JceTlsBlockCipher(context, "DESede", createDESedeBlockCipher(), createDESedeBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), 24);
    }

    protected JceTlsNullCipher createNullCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new JceTlsNullCipher(context, createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm));
    }

    protected JceTlsStreamCipher createRC4Cipher(int cipherKeySize, int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new JceTlsStreamCipher(context, createRC4StreamCipher(), createRC4StreamCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize, false);
    }

    protected JceTlsBlockCipher createSEEDCipher(int macAlgorithm)
        throws IOException, GeneralSecurityException
    {
        return new JceTlsBlockCipher(context, "SEED", createSEEDBlockCipher(), createSEEDBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), 16);
    }

    protected BlockCipher createAESEngine()
     {
         return new AESEngine();
     }

     protected BlockCipher createCamelliaEngine()
     {
         return new CamelliaEngine();
     }

     protected Cipher createAESBlockCipher()
         throws GeneralSecurityException
     {
         return this.getHelper().createCipher("AES/CBC/NoPadding");
     }

    protected Cipher createCamelliaBlockCipher()
        throws GeneralSecurityException
    {
        return this.getHelper().createCipher("Camellia/CBC/NoPadding");
    }

    protected Cipher createDESedeBlockCipher()
        throws GeneralSecurityException
    {
        return this.getHelper().createCipher("DESede/CBC/NoPadding");
    }

    protected Cipher createSEEDBlockCipher()
        throws GeneralSecurityException
    {
        return this.getHelper().createCipher("SEED/CBC/NoPadding");
    }

     protected AEADBlockCipher createAEADBlockCipher_AES_CCM()
     {
         return new CCMBlockCipher(createAESEngine());
     }

     protected AEADBlockCipher createAEADBlockCipher_AES_GCM()
     {
         // TODO Consider allowing custom configuration of multiplier
         return new GCMBlockCipher(createAESEngine());
     }

     protected AEADBlockCipher createAEADBlockCipher_AES_OCB()
     {
         return new OCBBlockCipher(createAESEngine(), createAESEngine());
     }

     protected AEADBlockCipher createAEADBlockCipher_Camellia_GCM()
     {
         // TODO Consider allowing custom configuration of multiplier
         return new GCMBlockCipher(createCamelliaEngine());
     }

     protected StreamCipher createRC4StreamCipher()
     {
         return new RC4Engine();
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
        throw new UnsupportedOperationException();
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

        @Override
        public void update(byte[] data, int offSet, int length)
        {
            digest.update(data, offSet, length);
        }

        @Override
        public byte[] calculateHash()
        {
            return digest.digest();
        }

        @Override
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

        @Override
        public void reset()
        {
            digest.reset();
        }
    }
}
