package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmSpec for the Unbalanced Oil and Vinegar (UOV) signature scheme.
 * Twelve canonical specs, one per parameter set × encoding-variant pair.
 */
public class UOVParameterSpec
    implements AlgorithmParameterSpec
{
    public static final UOVParameterSpec uov_Is = new UOVParameterSpec("UOV-IS");
    public static final UOVParameterSpec uov_Is_pkc = new UOVParameterSpec("UOV-IS-PKC");
    public static final UOVParameterSpec uov_Is_pkc_skc = new UOVParameterSpec("UOV-IS-PKC-SKC");

    public static final UOVParameterSpec uov_Ip = new UOVParameterSpec("UOV-IP");
    public static final UOVParameterSpec uov_Ip_pkc = new UOVParameterSpec("UOV-IP-PKC");
    public static final UOVParameterSpec uov_Ip_pkc_skc = new UOVParameterSpec("UOV-IP-PKC-SKC");

    public static final UOVParameterSpec uov_III = new UOVParameterSpec("UOV-III");
    public static final UOVParameterSpec uov_III_pkc = new UOVParameterSpec("UOV-III-PKC");
    public static final UOVParameterSpec uov_III_pkc_skc = new UOVParameterSpec("UOV-III-PKC-SKC");

    public static final UOVParameterSpec uov_V = new UOVParameterSpec("UOV-V");
    public static final UOVParameterSpec uov_V_pkc = new UOVParameterSpec("UOV-V-PKC");
    public static final UOVParameterSpec uov_V_pkc_skc = new UOVParameterSpec("UOV-V-PKC-SKC");

    private static final Map<String, UOVParameterSpec> parameters = new HashMap<String, UOVParameterSpec>();

    static
    {
        // canonical lower-case names match UOVParameters.getName()
        parameters.put("uov-is",          uov_Is);
        parameters.put("uov-is-pkc",      uov_Is_pkc);
        parameters.put("uov-is-pkc-skc",  uov_Is_pkc_skc);
        parameters.put("uov-ip",          uov_Ip);
        parameters.put("uov-ip-pkc",      uov_Ip_pkc);
        parameters.put("uov-ip-pkc-skc",  uov_Ip_pkc_skc);
        parameters.put("uov-iii",         uov_III);
        parameters.put("uov-iii-pkc",     uov_III_pkc);
        parameters.put("uov-iii-pkc-skc", uov_III_pkc_skc);
        parameters.put("uov-v",           uov_V);
        parameters.put("uov-v-pkc",       uov_V_pkc);
        parameters.put("uov-v-pkc-skc",   uov_V_pkc_skc);
    }

    private final String name;

    private UOVParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public static UOVParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }
        UOVParameterSpec spec = parameters.get(Strings.toLowerCase(name));
        if (spec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }
        return spec;
    }
}
