package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CombinedHash;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsCrypto
    extends AbstractTlsCrypto
{
    public BcTlsSecret adoptSecret(byte[] data)
    {
        return new BcTlsSecret(this, data);
    }

    public byte[] calculateDigest(short hashAlgorithm, byte[] buf, int off, int len) throws IOException
    {
        Digest d = createHash(hashAlgorithm);
        d.update(buf, off, len);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        return result;
    }

    public TlsCertificate createCertificate(byte[] encoding)
    {
        return new BcTlsCertificate(encoding);
    }

    public TlsCipher createCipher(int encryptionAlgorithm, int macAlgorithm) throws IOException
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

    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig)
    {
        return new BcTlsDHDomain(this, dhConfig);
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        return new BcTlsECDomain(this, ecConfig);
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

    public TlsContext getContext()
    {
        return context;
    }

//    public byte[] calculateKeyBlock(TlsContext context, int length)
//    {
//        SecurityParameters securityParameters = context.getSecurityParameters();
//        byte[] master_secret = securityParameters.getMasterSecret();
//        byte[] seed = concat(securityParameters.getServerRandom(), securityParameters.getClientRandom());
//
//        if (isSSL(context))
//        {
//            return context.getCrypto().createSecret(master_secret).deriveSSLKeyBlock(seed, length).extract();
//        }
//
//        return PRF(context, master_secret, ExporterLabel.key_expansion, seed, length);
//    }

    public Digest createHash(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return new MD5Digest();
        case HashAlgorithm.sha1:
            return new SHA1Digest();
        case HashAlgorithm.sha224:
            return new SHA224Digest();
        case HashAlgorithm.sha256:
            return new SHA256Digest();
        case HashAlgorithm.sha384:
            return new SHA384Digest();
        case HashAlgorithm.sha512:
            return new SHA512Digest();
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public Digest createHash(SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        return signatureAndHashAlgorithm == null ? new CombinedHash() : createHash(signatureAndHashAlgorithm.getHash());
    }

    public Digest cloneHash(short hashAlgorithm, Digest hash)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return new MD5Digest((MD5Digest)hash);
        case HashAlgorithm.sha1:
            return new SHA1Digest((SHA1Digest)hash);
        case HashAlgorithm.sha224:
            return new SHA224Digest((SHA224Digest)hash);
        case HashAlgorithm.sha256:
            return new SHA256Digest((SHA256Digest)hash);
        case HashAlgorithm.sha384:
            return new SHA384Digest((SHA384Digest)hash);
        case HashAlgorithm.sha512:
            return new SHA512Digest((SHA512Digest)hash);
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }

    public Digest createPRFHash(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case PRFAlgorithm.tls_prf_legacy:
            return new CombinedHash();
        default:
            return createHash(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));
        }
    }

    protected TlsBlockCipher createAESCipher(int cipherKeySize, int macAlgorithm) throws IOException
    {
        return new TlsBlockCipher(context, createAESBlockCipher(), createAESBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize);
    }

    protected TlsBlockCipher createCamelliaCipher(int cipherKeySize, int macAlgorithm) throws IOException
    {
        return new TlsBlockCipher(context, createCamelliaBlockCipher(), createCamelliaBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createChaCha20Poly1305() throws IOException
    {
        return new Chacha20Poly1305(context);
    }

    protected TlsAEADCipher createCipher_AES_CCM(int cipherKeySize, int macSize) throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_AES_CCM(), createAEADBlockCipher_AES_CCM(),
            cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_GCM(int cipherKeySize, int macSize) throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_AES_GCM(), createAEADBlockCipher_AES_GCM(),
            cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_OCB(int cipherKeySize, int macSize) throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_AES_OCB(), createAEADBlockCipher_AES_OCB(),
            cipherKeySize, macSize, TlsAEADCipher.NONCE_RFC7905);
    }

    protected TlsAEADCipher createCipher_Camellia_GCM(int cipherKeySize, int macSize) throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_Camellia_GCM(), createAEADBlockCipher_Camellia_GCM(),
            cipherKeySize, macSize);
    }

    protected TlsBlockCipher createDESedeCipher(int macAlgorithm) throws IOException
    {
        return new TlsBlockCipher(context, createDESedeBlockCipher(), createDESedeBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), 24);
    }

    protected TlsNullCipher createNullCipher(int macAlgorithm) throws IOException
    {
        return new TlsNullCipher(context, createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm));
    }

    protected TlsStreamCipher createRC4Cipher(int cipherKeySize, int macAlgorithm) throws IOException
    {
        return new TlsStreamCipher(context, createRC4StreamCipher(), createRC4StreamCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize, false);
    }

    protected TlsBlockCipher createSEEDCipher(int macAlgorithm) throws IOException
    {
        return new TlsBlockCipher(context, createSEEDBlockCipher(), createSEEDBlockCipher(),
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

    protected BlockCipher createAESBlockCipher()
    {
        return new CBCBlockCipher(createAESEngine());
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

    protected BlockCipher createCamelliaBlockCipher()
    {
        return new CBCBlockCipher(createCamelliaEngine());
    }

    protected BlockCipher createDESedeBlockCipher()
    {
        return new CBCBlockCipher(new DESedeEngine());
    }

    protected StreamCipher createRC4StreamCipher()
    {
        return new RC4Engine();
    }

    protected BlockCipher createSEEDBlockCipher()
    {
        return new CBCBlockCipher(new SEEDEngine());
    }

    protected Digest createHMACDigest(int macAlgorithm) throws IOException
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm._null:
            return null;
        case MACAlgorithm.hmac_md5:
            return TlsUtils.createHash(HashAlgorithm.md5);
        case MACAlgorithm.hmac_sha1:
            return TlsUtils.createHash(HashAlgorithm.sha1);
        case MACAlgorithm.hmac_sha256:
            return TlsUtils.createHash(HashAlgorithm.sha256);
        case MACAlgorithm.hmac_sha384:
            return TlsUtils.createHash(HashAlgorithm.sha384);
        case MACAlgorithm.hmac_sha512:
            return TlsUtils.createHash(HashAlgorithm.sha512);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
