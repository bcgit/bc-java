package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.util.Arrays;

public class TlsRSASigner extends AbstractTlsSigner {

    public byte[] generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1) throws CryptoException {

        AsymmetricBlockCipher engine = createRSAImpl();
        engine.init(true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
        return engine.processBlock(md5AndSha1, 0, md5AndSha1.length);
    }

    public boolean verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1)
        throws CryptoException {

        AsymmetricBlockCipher engine = createRSAImpl();
        engine.init(false, publicKey);
        byte[] signed = engine.processBlock(sigBytes, 0, sigBytes.length);
        return Arrays.constantTimeAreEqual(signed, md5AndSha1);
    }

    public Signer createSigner(AsymmetricKeyParameter privateKey) {
        return makeSigner(new CombinedHash(), true,
            new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
    }

    public Signer createVerifyer(AsymmetricKeyParameter publicKey) {
        return makeSigner(new CombinedHash(), false, publicKey);
    }

    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey) {
        return publicKey instanceof RSAKeyParameters && !publicKey.isPrivate();
    }

    protected Signer makeSigner(Digest d, boolean forSigning, CipherParameters cp) {
        Signer s = new GenericSigner(createRSAImpl(), d);
        s.init(forSigning, cp);
        return s;
    }

    protected AsymmetricBlockCipher createRSAImpl() {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
