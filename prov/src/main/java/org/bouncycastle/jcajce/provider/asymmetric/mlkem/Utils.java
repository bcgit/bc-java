package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

class Utils
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(MLKEMParameterSpec.ml_kem_512.getName(), MLKEMParameters.ml_kem_512);
        parameters.put(MLKEMParameterSpec.ml_kem_768.getName(), MLKEMParameters.ml_kem_768);
        parameters.put(MLKEMParameterSpec.ml_kem_1024.getName(), MLKEMParameters.ml_kem_1024);
    }

    static MLKEMParameters getParameters(String name)
    {
        return (MLKEMParameters)parameters.get(name);
    }
}
