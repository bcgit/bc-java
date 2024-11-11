package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;

class Utils
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(MLDSAParameterSpec.ml_dsa_44.getName(), MLDSAParameters.ml_dsa_44);
        parameters.put(MLDSAParameterSpec.ml_dsa_65.getName(), MLDSAParameters.ml_dsa_65);
        parameters.put(MLDSAParameterSpec.ml_dsa_87.getName(), MLDSAParameters.ml_dsa_87);
        parameters.put(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), MLDSAParameters.ml_dsa_44_with_sha512);
        parameters.put(MLDSAParameterSpec.ml_dsa_65_with_sha512.getName(), MLDSAParameters.ml_dsa_65_with_sha512);
        parameters.put(MLDSAParameterSpec.ml_dsa_87_with_sha512.getName(), MLDSAParameters.ml_dsa_87_with_sha512);
    }

    static MLDSAParameters getParameters(String paramName)
    {
        return (MLDSAParameters)parameters.get(paramName);
    }
}
