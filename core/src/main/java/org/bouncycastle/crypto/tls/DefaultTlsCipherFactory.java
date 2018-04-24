package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;

public class DefaultTlsCipherFactory
    extends AbstractTlsCipherFactory
{
    public TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        switch (encryptionAlgorithm)
        {
        case EncryptionAlgorithm._3DES_EDE_CBC:
            return createDESedeCipher(context, macAlgorithm);
        case EncryptionAlgorithm.AES_128_CBC:
            return createAESCipher(context, 16, macAlgorithm);
        case EncryptionAlgorithm.AES_128_CCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(context, 16, 16);
        case EncryptionAlgorithm.AES_128_CCM_8:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(context, 16, 8);
        case EncryptionAlgorithm.AES_128_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_GCM(context, 16, 16);
        case EncryptionAlgorithm.AES_128_OCB_TAGLEN96:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_OCB(context, 16, 12);
        case EncryptionAlgorithm.AES_256_CBC:
            return createAESCipher(context, 32, macAlgorithm);
        case EncryptionAlgorithm.AES_256_CCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(context, 32, 16);
        case EncryptionAlgorithm.AES_256_CCM_8:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_CCM(context, 32, 8);
        case EncryptionAlgorithm.AES_256_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_GCM(context, 32, 16);
        case EncryptionAlgorithm.AES_256_OCB_TAGLEN96:
            // NOTE: Ignores macAlgorithm
            return createCipher_AES_OCB(context, 32, 12);
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
            return createCamelliaCipher(context, 16, macAlgorithm);
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_Camellia_GCM(context, 16, 16);
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            return createCamelliaCipher(context, 32, macAlgorithm);
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
            // NOTE: Ignores macAlgorithm
            return createCipher_Camellia_GCM(context, 32, 16);
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            // NOTE: Ignores macAlgorithm
            return createChaCha20Poly1305(context);
        case EncryptionAlgorithm.NULL:
            return createNullCipher(context, macAlgorithm);
        case EncryptionAlgorithm.RC4_128:
            return createRC4Cipher(context, 16, macAlgorithm);
        case EncryptionAlgorithm.SEED_CBC:
            return createSEEDCipher(context, macAlgorithm);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsBlockCipher createAESCipher(TlsContext context, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(context, createAESBlockCipher(), createAESBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize);
    }

    protected TlsBlockCipher createCamelliaCipher(TlsContext context, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(context, createCamelliaBlockCipher(),
            createCamelliaBlockCipher(), createHMACDigest(macAlgorithm),
            createHMACDigest(macAlgorithm), cipherKeySize);
    }

    protected TlsCipher createChaCha20Poly1305(TlsContext context) throws IOException
    {
        return new Chacha20Poly1305(context);
    }

    protected TlsAEADCipher createCipher_AES_CCM(TlsContext context, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_AES_CCM(),
            createAEADBlockCipher_AES_CCM(), cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_GCM(TlsContext context, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_AES_GCM(),
            createAEADBlockCipher_AES_GCM(), cipherKeySize, macSize);
    }

    protected TlsAEADCipher createCipher_AES_OCB(TlsContext context, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_AES_OCB(),
            createAEADBlockCipher_AES_OCB(), cipherKeySize, macSize, TlsAEADCipher.NONCE_DRAFT_CHACHA20_POLY1305);
    }

    protected TlsAEADCipher createCipher_Camellia_GCM(TlsContext context, int cipherKeySize, int macSize)
        throws IOException
    {
        return new TlsAEADCipher(context, createAEADBlockCipher_Camellia_GCM(),
            createAEADBlockCipher_Camellia_GCM(), cipherKeySize, macSize);
    }

    protected TlsBlockCipher createDESedeCipher(TlsContext context, int macAlgorithm)
        throws IOException
    {
        return new TlsBlockCipher(context, createDESedeBlockCipher(), createDESedeBlockCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), 24);
    }

    protected TlsNullCipher createNullCipher(TlsContext context, int macAlgorithm)
        throws IOException
    {
        return new TlsNullCipher(context, createHMACDigest(macAlgorithm),
            createHMACDigest(macAlgorithm));
    }

    protected TlsStreamCipher createRC4Cipher(TlsContext context, int cipherKeySize, int macAlgorithm)
        throws IOException
    {
        return new TlsStreamCipher(context, createRC4StreamCipher(), createRC4StreamCipher(),
            createHMACDigest(macAlgorithm), createHMACDigest(macAlgorithm), cipherKeySize, false);
    }

    protected TlsBlockCipher createSEEDCipher(TlsContext context, int macAlgorithm)
        throws IOException
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
