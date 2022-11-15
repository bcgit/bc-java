package org.bouncycastle.pqc.crypto.cmce;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class CMCEKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{

    private CMCEKeyGenerationParameters cmceParams;

//    private int m;
//
//    private int n;
//
//    private int t;

    private SecureRandom random;

    private void initialize(
            KeyGenerationParameters param)
    {
        this.cmceParams = (CMCEKeyGenerationParameters) param;
        this.random = param.getRandom();

//        this.m = this.cmceParams.getParameters().getM();
//        this.n = this.cmceParams.getParameters().getN();
//        this.t = this.cmceParams.getParameters().getT();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        CMCEEngine engine = cmceParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(pk, sk, random);

        CMCEPublicKeyParameters pubKey = new CMCEPublicKeyParameters(cmceParams.getParameters(), pk);
        CMCEPrivateKeyParameters privKey = new CMCEPrivateKeyParameters(cmceParams.getParameters(), sk);
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
