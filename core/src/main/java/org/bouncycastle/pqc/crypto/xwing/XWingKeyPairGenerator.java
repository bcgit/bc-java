package org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

public class XWingKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        MLKEMKeyPairGenerator kyberKeyGen = new MLKEMKeyPairGenerator();

        kyberKeyGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));

        X25519KeyPairGenerator x25519KeyGen = new X25519KeyPairGenerator();

        x25519KeyGen.init(new X25519KeyGenerationParameters(random));

        AsymmetricCipherKeyPair kybKp = kyberKeyGen.generateKeyPair();
        AsymmetricCipherKeyPair xdhKp = x25519KeyGen.generateKeyPair();

        return new AsymmetricCipherKeyPair(
            new XWingPublicKeyParameters(kybKp.getPublic(), xdhKp.getPublic()),
            new XWingPrivateKeyParameters(kybKp.getPrivate(), xdhKp.getPrivate()));
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }

}
