package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.util.Strings;

public class HQCParameterSpec
    implements AlgorithmParameterSpec
{
    public static final HQCParameterSpec hqc128 = new HQCParameterSpec(HQCParameters.hqc128);
    public static final HQCParameterSpec hqc192 = new HQCParameterSpec(HQCParameters.hqc192);
    public static final HQCParameterSpec hqc256 = new HQCParameterSpec(HQCParameters.hqc256);

    private static Map parameters = new HashMap();

    static
    {
        // getName() returns the HQCParameters name (e.g. "hqc-128"), so the dashed form
        // must be a key for fromName(getName()) to round-trip; the un-dashed names are
        // kept as aliases.
        parameters.put("hqc-128", hqc128);
        parameters.put("hqc-192", hqc192);
        parameters.put("hqc-256", hqc256);

        parameters.put("hqc128", hqc128);
        parameters.put("hqc192", hqc192);
        parameters.put("hqc256", hqc256);
    }

    private final String name;

    private HQCParameterSpec(HQCParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static HQCParameterSpec fromName(String name)
    {
        return (HQCParameterSpec) parameters.get(Strings.toLowerCase(name));
    }
}
