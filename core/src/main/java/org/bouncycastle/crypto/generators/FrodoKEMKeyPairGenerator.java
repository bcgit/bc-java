package org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;
import org.bouncycastle.crypto.params.FrodoKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMPublicKeyParameters;

public class FrodoKEMKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private FrodoKEMParameters frodoParams;

    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.frodoParams = ((FrodoKEMKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        FrodoKEMEngine engine = FrodoKEMEngine.getInstance(frodoParams);
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(pk, sk, random);

        FrodoKEMPublicKeyParameters pubKey = new FrodoKEMPublicKeyParameters(frodoParams, pk);
        FrodoKEMPrivateKeyParameters privKey = new FrodoKEMPrivateKeyParameters(frodoParams, sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }
}
