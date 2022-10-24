package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.util.Strings;

public class FalconParameterSpec
    implements AlgorithmParameterSpec
{
    public static final FalconParameterSpec falcon_512 = new FalconParameterSpec(FalconParameters.falcon_512);
    public static final FalconParameterSpec falcon_1024 = new FalconParameterSpec(FalconParameters.falcon_1024);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("falcon-512", falcon_512);
        parameters.put("falcon-1024", falcon_1024);
    }

    private final String name;

    private FalconParameterSpec(FalconParameters parameters)
    {
        this.name = Strings.toUpperCase(parameters.getName());
    }

    public String getName()
    {
        return name;
    }

    public static FalconParameterSpec fromName(String name)
    {
        return (FalconParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
