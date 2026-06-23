package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmSpec for the standardised Classic McEliece (ISO/IEC 18033-2:2006/Amd 2:2026, Clause 13).
 * Each of the four security parameter sets has a base variant, a semi-systematic "f" variant, a
 * plaintext-confirmation "pc" variant, and a combined "pcf" variant.
 */
public class CMCEParameterSpec
    implements AlgorithmParameterSpec
{
    public static final CMCEParameterSpec mceliece460896 = new CMCEParameterSpec("mceliece460896");
    public static final CMCEParameterSpec mceliece460896f = new CMCEParameterSpec("mceliece460896f");
    public static final CMCEParameterSpec mceliece460896pc = new CMCEParameterSpec("mceliece460896pc");
    public static final CMCEParameterSpec mceliece460896pcf = new CMCEParameterSpec("mceliece460896pcf");
    public static final CMCEParameterSpec mceliece6688128 = new CMCEParameterSpec("mceliece6688128");
    public static final CMCEParameterSpec mceliece6688128f = new CMCEParameterSpec("mceliece6688128f");
    public static final CMCEParameterSpec mceliece6688128pc = new CMCEParameterSpec("mceliece6688128pc");
    public static final CMCEParameterSpec mceliece6688128pcf = new CMCEParameterSpec("mceliece6688128pcf");
    public static final CMCEParameterSpec mceliece6960119 = new CMCEParameterSpec("mceliece6960119");
    public static final CMCEParameterSpec mceliece6960119f = new CMCEParameterSpec("mceliece6960119f");
    public static final CMCEParameterSpec mceliece6960119pc = new CMCEParameterSpec("mceliece6960119pc");
    public static final CMCEParameterSpec mceliece6960119pcf = new CMCEParameterSpec("mceliece6960119pcf");
    public static final CMCEParameterSpec mceliece8192128 = new CMCEParameterSpec("mceliece8192128");
    public static final CMCEParameterSpec mceliece8192128f = new CMCEParameterSpec("mceliece8192128f");
    public static final CMCEParameterSpec mceliece8192128pc = new CMCEParameterSpec("mceliece8192128pc");
    public static final CMCEParameterSpec mceliece8192128pcf = new CMCEParameterSpec("mceliece8192128pcf");

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("mceliece460896", mceliece460896);
        parameters.put("mceliece460896f", mceliece460896f);
        parameters.put("mceliece460896pc", mceliece460896pc);
        parameters.put("mceliece460896pcf", mceliece460896pcf);
        parameters.put("mceliece6688128", mceliece6688128);
        parameters.put("mceliece6688128f", mceliece6688128f);
        parameters.put("mceliece6688128pc", mceliece6688128pc);
        parameters.put("mceliece6688128pcf", mceliece6688128pcf);
        parameters.put("mceliece6960119", mceliece6960119);
        parameters.put("mceliece6960119f", mceliece6960119f);
        parameters.put("mceliece6960119pc", mceliece6960119pc);
        parameters.put("mceliece6960119pcf", mceliece6960119pcf);
        parameters.put("mceliece8192128", mceliece8192128);
        parameters.put("mceliece8192128f", mceliece8192128f);
        parameters.put("mceliece8192128pc", mceliece8192128pc);
        parameters.put("mceliece8192128pcf", mceliece8192128pcf);
    }

    private final String name;

    private CMCEParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public static CMCEParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }

        CMCEParameterSpec parameterSpec = (CMCEParameterSpec)parameters.get(Strings.toLowerCase(name));

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }

        return parameterSpec;
    }
}
