package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;

class TlsRSASigner extends AbstractTlsSigner {

    public byte[] calculateRawSignature(SecureRandom random, AsymmetricKeyParameter privateKey, byte[] md5andsha1)
        throws CryptoException {

        AsymmetricBlockCipher engine = createEngine();
        engine.init(true, new ParametersWithRandom(privateKey, random));
        return engine.processBlock(md5andsha1, 0, md5andsha1.length);
    }

    public Signer createVerifyer(AsymmetricKeyParameter publicKey) {

        AsymmetricBlockCipher engine = createEngine();
        Signer s = new GenericSigner(engine, new CombinedHash());
        s.init(false, publicKey);
        return s;
    }

    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey) {
        return publicKey instanceof RSAKeyParameters && !publicKey.isPrivate();
    }

    protected AsymmetricBlockCipher createEngine() {
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
