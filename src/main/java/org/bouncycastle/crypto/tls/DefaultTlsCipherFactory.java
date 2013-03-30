package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;

public class DefaultTlsCipherFactory extends AbstractTlsCipherFactory {
    public TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int digestAlgorithm)
        throws IOException {
        switch (encryptionAlgorithm) {
        case EncryptionAlgorithm._3DES_EDE_CBC:
            return createDESedeCipher(context, digestAlgorithm);
        case EncryptionAlgorithm.AES_128_CBC:
            return createAESCipher(context, 16, digestAlgorithm);
        case EncryptionAlgorithm.AES_256_CBC:
            return createAESCipher(context, 32, digestAlgorithm);
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
            return createCamelliaCipher(context, 16, digestAlgorithm);
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
            return createCamelliaCipher(context, 32, digestAlgorithm);
        case EncryptionAlgorithm.NULL:
            return createNullCipher(context, digestAlgorithm);
        case EncryptionAlgorithm.RC4_128:
            return createRC4Cipher(context, 16, digestAlgorithm);
        case EncryptionAlgorithm.SEED_CBC:
            return createSEEDCipher(context, digestAlgorithm);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCipher createAEADCipher(TlsContext context, int encryptionAlgorithm, int prfAlgorithm)
        throws IOException {

        switch (encryptionAlgorithm) {
        case EncryptionAlgorithm.AES_128_GCM:
            return createCipher_AES_GCM(context, 16, 16, prfAlgorithm);
        case EncryptionAlgorithm.AES_256_GCM:
            return createCipher_AES_GCM(context, 32, 16, prfAlgorithm);
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsCipher createAESCipher(TlsContext context, int cipherKeySize, int digestAlgorithm)
        throws IOException {
        return new TlsBlockCipher(context, createAESBlockCipher(), createAESBlockCipher(),
            createDigest(digestAlgorithm), createDigest(digestAlgorithm), cipherKeySize);
    }

    protected TlsCipher createCipher_AES_GCM(TlsContext context, int cipherKeySize, int macSize,
        int prfAlgorithm) throws IOException {
        return new TlsAEADCipher(context, createAEADBlockCipher_AES_GCM(),
            createAEADBlockCipher_AES_GCM(), cipherKeySize, macSize, prfAlgorithm);
    }

    protected TlsCipher createCamelliaCipher(TlsContext context, int cipherKeySize,
        int digestAlgorithm) throws IOException {
        return new TlsBlockCipher(context, createCamelliaBlockCipher(),
            createCamelliaBlockCipher(), createDigest(digestAlgorithm),
            createDigest(digestAlgorithm), cipherKeySize);
    }

    protected TlsCipher createNullCipher(TlsContext context, int digestAlgorithm)
        throws IOException {
        return new TlsNullCipher(context, createDigest(digestAlgorithm),
            createDigest(digestAlgorithm));
    }

    protected TlsCipher createRC4Cipher(TlsContext context, int cipherKeySize, int digestAlgorithm)
        throws IOException {
        return new TlsStreamCipher(context, createRC4StreamCipher(), createRC4StreamCipher(),
            createDigest(digestAlgorithm), createDigest(digestAlgorithm), cipherKeySize);
    }

    protected TlsCipher createDESedeCipher(TlsContext context, int digestAlgorithm)
        throws IOException {
        return new TlsBlockCipher(context, createDESedeBlockCipher(), createDESedeBlockCipher(),
            createDigest(digestAlgorithm), createDigest(digestAlgorithm), 24);
    }

    protected TlsCipher createSEEDCipher(TlsContext context, int digestAlgorithm)
        throws IOException {
        return new TlsBlockCipher(context, createSEEDBlockCipher(), createSEEDBlockCipher(),
            createDigest(digestAlgorithm), createDigest(digestAlgorithm), 16);
    }

    protected StreamCipher createRC4StreamCipher() {
        return new RC4Engine();
    }

    protected BlockCipher createAESBlockCipher() {
        return new CBCBlockCipher(new AESFastEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_AES_GCM() {
        // TODO Consider allowing custom configuration of multiplier
        return new GCMBlockCipher(new AESFastEngine());
    }

    protected BlockCipher createCamelliaBlockCipher() {
        return new CBCBlockCipher(new CamelliaEngine());
    }

    protected BlockCipher createDESedeBlockCipher() {
        return new CBCBlockCipher(new DESedeEngine());
    }

    protected BlockCipher createSEEDBlockCipher() {
        return new CBCBlockCipher(new SEEDEngine());
    }

    protected Digest createDigest(int macAlgorithm) throws IOException {
        switch (macAlgorithm) {
        case MACAlgorithm.NULL:
            return null;
        case MACAlgorithm.hmac_md5:
            return new MD5Digest();
        case MACAlgorithm.hmac_sha1:
            return new SHA1Digest();
        case MACAlgorithm.hmac_sha256:
            return new SHA256Digest();
        case MACAlgorithm.hmac_sha384:
            return new SHA384Digest();
        case MACAlgorithm.hmac_sha512:
            return new SHA512Digest();
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
