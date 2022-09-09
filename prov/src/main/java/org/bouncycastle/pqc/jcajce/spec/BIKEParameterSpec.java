package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.util.Strings;

public class BIKEParameterSpec
    implements AlgorithmParameterSpec
{
    public static final BIKEParameterSpec bike128 = new BIKEParameterSpec(BIKEParameters.bike128);
    public static final BIKEParameterSpec bike192 = new BIKEParameterSpec(BIKEParameters.bike192);
    public static final BIKEParameterSpec bike256 = new BIKEParameterSpec(BIKEParameters.bike256);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("bike128", bike128);
        parameters.put("bike192", bike192);
        parameters.put("bike256", bike256);
    }

    private final String name;

    private BIKEParameterSpec(BIKEParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static BIKEParameterSpec fromName(String name)
    {
        return (BIKEParameterSpec) parameters.get(Strings.toLowerCase(name));
    }
}
