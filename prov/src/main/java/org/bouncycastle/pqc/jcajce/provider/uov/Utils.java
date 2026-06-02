package org.bouncycastle.pqc.jcajce.provider.uov;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.uov.UOVParameters;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;

class Utils
{
    private static final Map<String, UOVParameters> parameters = new HashMap<String, UOVParameters>();

    static
    {
        parameters.put(UOVParameterSpec.uov_Is.getName(),          UOVParameters.uov_Is);
        parameters.put(UOVParameterSpec.uov_Is_pkc.getName(),      UOVParameters.uov_Is_pkc);
        parameters.put(UOVParameterSpec.uov_Is_pkc_skc.getName(),  UOVParameters.uov_Is_pkc_skc);
        parameters.put(UOVParameterSpec.uov_Ip.getName(),          UOVParameters.uov_Ip);
        parameters.put(UOVParameterSpec.uov_Ip_pkc.getName(),      UOVParameters.uov_Ip_pkc);
        parameters.put(UOVParameterSpec.uov_Ip_pkc_skc.getName(),  UOVParameters.uov_Ip_pkc_skc);
        parameters.put(UOVParameterSpec.uov_III.getName(),         UOVParameters.uov_III);
        parameters.put(UOVParameterSpec.uov_III_pkc.getName(),     UOVParameters.uov_III_pkc);
        parameters.put(UOVParameterSpec.uov_III_pkc_skc.getName(), UOVParameters.uov_III_pkc_skc);
        parameters.put(UOVParameterSpec.uov_V.getName(),           UOVParameters.uov_V);
        parameters.put(UOVParameterSpec.uov_V_pkc.getName(),       UOVParameters.uov_V_pkc);
        parameters.put(UOVParameterSpec.uov_V_pkc_skc.getName(),   UOVParameters.uov_V_pkc_skc);
    }

    static UOVParameters getParameters(String name)
    {
        return (UOVParameters)parameters.get(name);
    }
}
