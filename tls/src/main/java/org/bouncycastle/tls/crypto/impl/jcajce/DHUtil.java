package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.tls.crypto.DHGroup;

class DHUtil
{
    static AlgorithmParameterSpec createInitSpec(DHGroup dhGroup)
    {
        // NOTE: dhGroup.getQ() is ignored here
        return new DHParameterSpec(dhGroup.getP(), dhGroup.getG(), dhGroup.getL());
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, DHGroup dhGroup)
    {
        return getAlgorithmParameters(crypto, createInitSpec(dhGroup));
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec)
    {
        try
        {
            AlgorithmParameters dhAlgParams = crypto.getHelper().createAlgorithmParameters("DiffieHellman");
            dhAlgParams.init(initSpec);

            DHParameterSpec dhSpec = dhAlgParams.getParameterSpec(DHParameterSpec.class);
            if (null != dhSpec)
            {
                return dhAlgParams;
            }
        }
        catch (Exception e)
        {
        }

        return null;
    }

    static DHParameterSpec getDHParameterSpec(JcaTlsCrypto crypto, DHGroup dhGroup)
    {
        return getDHParameterSpec(crypto, createInitSpec(dhGroup));
    }

    static DHParameterSpec getDHParameterSpec(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec)
    {
        try
        {
            AlgorithmParameters dhAlgParams = crypto.getHelper().createAlgorithmParameters("DiffieHellman");
            dhAlgParams.init(initSpec);

            DHParameterSpec dhSpec = dhAlgParams.getParameterSpec(DHParameterSpec.class);
            if (null != dhSpec)
            {
                return dhSpec;
            }
        }
        catch (Exception e)
        {
        }

        return null;
    }
}
