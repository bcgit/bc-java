package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class FrodoKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private  FrodoKeyGenerationParameters frodoParams;

    private int n;

    private boolean isAES128;

    private SecureRandom random;

    private void initialize(
            KeyGenerationParameters param)
    {
        this.frodoParams = (FrodoKeyGenerationParameters) param;
        this.random = param.getRandom();

        this.n = this.frodoParams.getParameters().getN();
        this.isAES128 = this.frodoParams.getParameters().isAES128();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        FrodoEngine engine = frodoParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(pk, sk, random);

        FrodoPublicKeyParameters pubKey = new FrodoPublicKeyParameters(pk, frodoParams.getParameters());
        FrodoPrivateKeyParameters privKey = new FrodoPrivateKeyParameters(sk, frodoParams.getParameters());
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }
    @Override
    public void init(KeyGenerationParameters param) { this.initialize(param); }

    public AsymmetricCipherKeyPair generateKeyPair() { return genKeyPair(); }

}
