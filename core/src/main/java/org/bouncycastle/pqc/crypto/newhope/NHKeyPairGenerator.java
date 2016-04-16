package org.bouncycastle.pqc.crypto.newhope;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class NHKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pubData = new byte[NewHope.SENDA_BYTES];
        short[] secData = new short[NewHope.POLY_SIZE];

        NewHope.keygen(random, pubData, secData);

        return new AsymmetricCipherKeyPair(new NHPublicKeyParameters(pubData), new NHPrivateKeyParameters(secData));
    }
}
