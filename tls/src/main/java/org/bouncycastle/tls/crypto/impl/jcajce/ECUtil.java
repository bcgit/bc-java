package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import org.bouncycastle.jcajce.util.JcaJceHelper;

class ECUtil
{
    static boolean isECPrivateKey(PrivateKey key)
    {
        return key instanceof ECPrivateKey || "EC".equals(key.getAlgorithm());
    }

    static boolean isCurveSupported(String curveName, JcaJceHelper helper)
    {
        try
        {
            AlgorithmParameters params = helper.createAlgorithmParameters("EC");
            params.init(new ECGenParameterSpec(curveName));
            if (params.getParameterSpec(ECParameterSpec.class) != null)
            {
                return true;
            }
        }
        catch (Exception e)
        {
        }

        return false;
    }
}
