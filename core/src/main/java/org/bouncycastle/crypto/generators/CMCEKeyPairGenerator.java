package org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.kems.cmce.CMCEEngine;
import org.bouncycastle.crypto.params.CMCEKeyGenerationParameters;
import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.crypto.params.CMCEPrivateKeyParameters;
import org.bouncycastle.crypto.params.CMCEPublicKeyParameters;

public class CMCEKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private CMCEParameters cmceParams;

    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.cmceParams = ((CMCEKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        CMCEEngine engine = CMCEEngine.getInstance(cmceParams);
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(pk, sk, random);

        CMCEPublicKeyParameters pubKey = new CMCEPublicKeyParameters(cmceParams, pk);
        CMCEPrivateKeyParameters privKey = new CMCEPrivateKeyParameters(cmceParams, sk);
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
