package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;
import java.security.AlgorithmParameters;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;

import org.bouncycastle.jcajce.util.JcaJceHelper;

class ECUtil
{
    static int[] convertMidTerms(int[] k)
    {
        int[] res = new int[3];

        if (k.length == 1)
        {
            res[0] = k[0];
        }
        else
        {
            if (k.length != 3)
            {
                throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
            }

            if (k[0] < k[1] && k[0] < k[2])
            {
                res[0] = k[0];
                if (k[1] < k[2])
                {
                    res[1] = k[1];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[1];
                }
            }
            else if (k[1] < k[2])
            {
                res[0] = k[1];
                if (k[0] < k[2])
                {
                    res[1] = k[0];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[0];
                }
            }
            else
            {
                res[0] = k[2];
                if (k[0] < k[1])
                {
                    res[1] = k[0];
                    res[2] = k[1];
                }
                else
                {
                    res[1] = k[1];
                    res[2] = k[0];
                }
            }
        }

        return res;
    }

    static AlgorithmParameterSpec createInitSpec(String curveName)
    {
        return new ECGenParameterSpec(curveName);
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, String curveName)
    {
        return getAlgorithmParameters(crypto, new ECGenParameterSpec(curveName));
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec)
    {
        try
        {
            AlgorithmParameters ecAlgParams = crypto.getHelper().createAlgorithmParameters("EC");
            ecAlgParams.init(initSpec);

            ECParameterSpec ecSpec = ecAlgParams.getParameterSpec(ECParameterSpec.class);
            if (null != ecSpec)
            {
                return ecAlgParams;
            }
        }
        catch (Exception e)
        {
        }

        return null;
    }

    static ECParameterSpec getECParameterSpec(JcaTlsCrypto crypto, String curveName)
    {
        return getECParameterSpec(crypto, createInitSpec(curveName));
    }

    static ECParameterSpec getECParameterSpec(JcaTlsCrypto crypto, AlgorithmParameterSpec initSpec)
    {
        // Try the "modern" way
        try
        {
            AlgorithmParameters ecAlgParams = crypto.getHelper().createAlgorithmParameters("EC");
            ecAlgParams.init(initSpec);

            ECParameterSpec ecSpec = ecAlgParams.getParameterSpec(ECParameterSpec.class);
            if (null != ecSpec)
            {
                return ecSpec;
            }
        }
        catch (Exception e)
        {
        }

        /*
         * Try a more round about way (the IBM JCE is an example of this).
         * 
         * NOTE: For these providers, we will not be able to provide an AlgorithmParameters object
         * to BCJSSE for use with AlgorithmConstraints checks, so curve constraints will not work.
         */
        try
        {
            KeyPairGenerator kpGen = crypto.getHelper().createKeyPairGenerator("EC");
            kpGen.initialize(initSpec, crypto.getSecureRandom());
            KeyPair kp = kpGen.generateKeyPair();
            return ((ECKey)kp.getPrivate()).getParams();
        }
        catch (Exception e)
        {
        }

        return null;
    }

    static boolean isECPrivateKey(PrivateKey key)
    {
        return key instanceof ECPrivateKey || "EC".equalsIgnoreCase(key.getAlgorithm());
    }

    static boolean isCurveSupported(JcaTlsCrypto crypto, String curveName)
    {
        return isCurveSupported(crypto, new ECGenParameterSpec(curveName));
    }

    static boolean isCurveSupported(JcaTlsCrypto crypto, ECGenParameterSpec initSpec)
    {
        return null != getECParameterSpec(crypto, initSpec);
    }
}
