package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;

class Utils
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(CMCEParameterSpec.mceliece460896.getName(), CMCEParameters.mceliece460896);
        parameters.put(CMCEParameterSpec.mceliece460896f.getName(), CMCEParameters.mceliece460896f);
        parameters.put(CMCEParameterSpec.mceliece460896pc.getName(), CMCEParameters.mceliece460896pc);
        parameters.put(CMCEParameterSpec.mceliece460896pcf.getName(), CMCEParameters.mceliece460896pcf);
        parameters.put(CMCEParameterSpec.mceliece6688128.getName(), CMCEParameters.mceliece6688128);
        parameters.put(CMCEParameterSpec.mceliece6688128f.getName(), CMCEParameters.mceliece6688128f);
        parameters.put(CMCEParameterSpec.mceliece6688128pc.getName(), CMCEParameters.mceliece6688128pc);
        parameters.put(CMCEParameterSpec.mceliece6688128pcf.getName(), CMCEParameters.mceliece6688128pcf);
        parameters.put(CMCEParameterSpec.mceliece6960119.getName(), CMCEParameters.mceliece6960119);
        parameters.put(CMCEParameterSpec.mceliece6960119f.getName(), CMCEParameters.mceliece6960119f);
        parameters.put(CMCEParameterSpec.mceliece6960119pc.getName(), CMCEParameters.mceliece6960119pc);
        parameters.put(CMCEParameterSpec.mceliece6960119pcf.getName(), CMCEParameters.mceliece6960119pcf);
        parameters.put(CMCEParameterSpec.mceliece8192128.getName(), CMCEParameters.mceliece8192128);
        parameters.put(CMCEParameterSpec.mceliece8192128f.getName(), CMCEParameters.mceliece8192128f);
        parameters.put(CMCEParameterSpec.mceliece8192128pc.getName(), CMCEParameters.mceliece8192128pc);
        parameters.put(CMCEParameterSpec.mceliece8192128pcf.getName(), CMCEParameters.mceliece8192128pcf);
    }

    static CMCEParameters getParameters(String name)
    {
        return (CMCEParameters)parameters.get(name);
    }
}
