package org.bouncycastle.pqc.crypto.frodo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class FrodoKeyPairGenerator
        implements AsymmetricCipherKeyPairGenerator
{
    private FrodoKeyGenerationParameters frodoParams;

    private int n;
    private int D;
    private int B;

    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.frodoParams = (FrodoKeyGenerationParameters)param;
        this.random = param.getRandom();

        this.n = this.frodoParams.getParameters().getN();
        this.D = this.frodoParams.getParameters().getD();
        this.B = this.frodoParams.getParameters().getB();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        FrodoEngine engine = frodoParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(pk, sk, random);

        FrodoPublicKeyParameters pubKey = new FrodoPublicKeyParameters(frodoParams.getParameters(), pk);
        FrodoPrivateKeyParameters privKey = new FrodoPrivateKeyParameters(frodoParams.getParameters(), sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);
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
