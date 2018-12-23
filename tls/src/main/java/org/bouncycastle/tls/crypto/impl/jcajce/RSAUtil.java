package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.tls.HashAlgorithm;

class RSAUtil
{
    static String getDigestSigAlgName(
        String name)
    {
        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return name;
    }


    static AlgorithmParameterSpec getPSSParameterSpec(short hash, String digestName)
    {
        MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(digestName);
        return new PSSParameterSpec(digestName, "MGF1", mgf1Spec, HashAlgorithm.getOutputSize(hash), 1);
    }
}
