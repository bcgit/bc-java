package org.bouncycastle.tls.crypto.impl.jcajce;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec;
import org.bouncycastle.tls.crypto.DHGroup;

class DHUtil
{
    static AlgorithmParameterSpec createInitSpec(DHGroup dhGroup)
    {
        // NOTE: A BC-specific spec, so other providers probably won't see Q 
        return new DHDomainParameterSpec(dhGroup.getP(), dhGroup.getQ(), dhGroup.getG(), dhGroup.getL());
    }

    static KeySpec createPublicKeySpec(BigInteger y, DHParameterSpec dhSpec)
    {
        // NOTE: A BC-specific spec, so other providers probably won't see Q 
        return new DHExtendedPublicKeySpec(y, dhSpec);
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

            DHParameterSpec dhSpec = (DHParameterSpec)dhAlgParams.getParameterSpec(DHParameterSpec.class);
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

            DHParameterSpec dhSpec = (DHParameterSpec)dhAlgParams.getParameterSpec(DHParameterSpec.class);
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

    static BigInteger getQ(DHParameterSpec dhSpec)
    {
        return dhSpec instanceof DHDomainParameterSpec ? ((DHDomainParameterSpec)dhSpec).getQ() : null;
    }
}
