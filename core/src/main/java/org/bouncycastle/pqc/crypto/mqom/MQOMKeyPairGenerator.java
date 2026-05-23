package org.bouncycastle.pqc.crypto.mqom;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMEngine;

public class MQOMKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MQOMParameters parameters;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        this.parameters = ((MQOMKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        MQOMEngine engine = MQOMEngine.getInstance(parameters);
        byte[] seedKey = new byte[2 * parameters.getSeedSize()];
        random.nextBytes(seedKey);

        byte[] pk = new byte[parameters.getPublicKeySize()];
        byte[] sk = new byte[parameters.getPrivateKeySize()];
        engine.keyGen(seedKey, sk, pk);

        return new AsymmetricCipherKeyPair(
            new MQOMPublicKeyParameters(parameters, pk),
            new MQOMPrivateKeyParameters(parameters, sk));
    }
}
