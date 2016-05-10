package com.github.gv2011.bcasn.crypto.generators;

import java.math.BigInteger;

import com.github.gv2011.bcasn.crypto.AsymmetricCipherKeyPair;
import com.github.gv2011.bcasn.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.gv2011.bcasn.crypto.KeyGenerationParameters;
import com.github.gv2011.bcasn.crypto.params.DHKeyGenerationParameters;
import com.github.gv2011.bcasn.crypto.params.DHParameters;
import com.github.gv2011.bcasn.crypto.params.DHPrivateKeyParameters;
import com.github.gv2011.bcasn.crypto.params.DHPublicKeyParameters;

/**
 * a Diffie-Hellman key pair generator.
 *
 * This generates keys consistent for use in the MTI/A0 key agreement protocol
 * as described in "Handbook of Applied Cryptography", Pages 516-519.
 */
public class DHKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DHKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DHKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        DHParameters dhp = param.getParameters();

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(y, dhp),
            new DHPrivateKeyParameters(x, dhp));
    }
}
