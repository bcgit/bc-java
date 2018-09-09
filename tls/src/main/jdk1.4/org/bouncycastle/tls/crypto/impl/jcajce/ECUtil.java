package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;
import java.security.AlgorithmParameters;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;

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
            params.init(new ECNamedCurveGenParameterSpec(curveName));
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
