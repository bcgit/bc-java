package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;

class Utils
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(FrodoKEMParameterSpec.frodokem976shake.getName(), FrodoKEMParameters.frodokem976shake);
        parameters.put(FrodoKEMParameterSpec.frodokem1344shake.getName(), FrodoKEMParameters.frodokem1344shake);
        parameters.put(FrodoKEMParameterSpec.efrodokem976shake.getName(), FrodoKEMParameters.efrodokem976shake);
        parameters.put(FrodoKEMParameterSpec.efrodokem1344shake.getName(), FrodoKEMParameters.efrodokem1344shake);
    }

    static FrodoKEMParameters getParameters(String name)
    {
        return (FrodoKEMParameters)parameters.get(name);
    }
}
