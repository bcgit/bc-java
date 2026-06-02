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
    public static final UOVParameterSpec uov_Is = new UOVParameterSpec("uov-is");
    public static final UOVParameterSpec uov_Is_pkc = new UOVParameterSpec("uov-is-pkc");
    public static final UOVParameterSpec uov_Is_pkc_skc = new UOVParameterSpec("uov-is-pkc-skc");

    public static final UOVParameterSpec uov_Ip = new UOVParameterSpec("uov-ip");
    public static final UOVParameterSpec uov_Ip_pkc = new UOVParameterSpec("uov-ip-pkc");
    public static final UOVParameterSpec uov_Ip_pkc_skc = new UOVParameterSpec("uov-ip-pkc-skc");

    public static final UOVParameterSpec uov_III = new UOVParameterSpec("uov-iii");
    public static final UOVParameterSpec uov_III_pkc = new UOVParameterSpec("uov-iii-pkc");
    public static final UOVParameterSpec uov_III_pkc_skc = new UOVParameterSpec("uov-iii-pkc-skc");

    public static final UOVParameterSpec uov_V = new UOVParameterSpec("uov-v");
    public static final UOVParameterSpec uov_V_pkc = new UOVParameterSpec("uov-v-pkc");
    public static final UOVParameterSpec uov_V_pkc_skc = new UOVParameterSpec("uov-v-pkc-skc");

    private static final Map<String, UOVParameterSpec> parameters = new HashMap<String, UOVParameterSpec>();

    static
    {
        parameters.put(uov_Is.getName(),          uov_Is);
        parameters.put(uov_Is_pkc.getName(),      uov_Is_pkc);
        parameters.put(uov_Is_pkc_skc.getName(),  uov_Is_pkc_skc);
        parameters.put(uov_Ip.getName(),          uov_Ip);
        parameters.put(uov_Ip_pkc.getName(),      uov_Ip_pkc);
        parameters.put(uov_Ip_pkc_skc.getName(),  uov_Ip_pkc_skc);
        parameters.put(uov_III.getName(),         uov_III);
        parameters.put(uov_III_pkc.getName(),     uov_III_pkc);
        parameters.put(uov_III_pkc_skc.getName(), uov_III_pkc_skc);
        parameters.put(uov_V.getName(),           uov_V);
        parameters.put(uov_V_pkc.getName(),       uov_V_pkc);
        parameters.put(uov_V_pkc_skc.getName(),   uov_V_pkc_skc);
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

    /**
     * @param name a parameter-set name (case-insensitive)
     * @return the matching spec, or {@code null} if {@code name} is null or unrecognised
     */
    public static UOVParameterSpec fromName(String name)
    {
        if (name == null)
        {
            return null;
        }
        return (UOVParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
