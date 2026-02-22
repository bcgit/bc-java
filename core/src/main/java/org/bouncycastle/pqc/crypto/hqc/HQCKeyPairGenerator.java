package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class HQCKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private HQCParameters parameters;

    @Override
    public void init(KeyGenerationParameters params)
    {
        this.random = params.getRandom();
        this.parameters = ((HQCKeyGenerationParameters)params).getParameters();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pk = new byte[parameters.getPublicKeyBytes()];
        byte[] sk = new byte[parameters.getSecretKeyBytes()];

        parameters.getEngine().genKeyPair(pk, sk, random);

        HQCPublicKeyParameters publicKey = new HQCPublicKeyParameters(parameters, pk);
        HQCPrivateKeyParameters privateKey = new HQCPrivateKeyParameters(parameters, sk);
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
