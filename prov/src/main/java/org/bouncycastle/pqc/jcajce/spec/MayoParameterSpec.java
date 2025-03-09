package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.mayo.MayoParameters;
import org.bouncycastle.util.Strings;

public class MayoParameterSpec
    implements AlgorithmParameterSpec
{
    public static final MayoParameterSpec mayo1 = new MayoParameterSpec(MayoParameters.mayo1);
    public static final MayoParameterSpec mayo2 = new MayoParameterSpec(MayoParameters.mayo2);
    public static final MayoParameterSpec mayo3 = new MayoParameterSpec(MayoParameters.mayo3);
    public static final MayoParameterSpec mayo5 = new MayoParameterSpec(MayoParameters.mayo5);

    private static Map parameters = new HashMap();

    static
    {
//        parameters.put("mayo1", mayo1);
//        parameters.put("mayo2", mayo2);
//        parameters.put("mayo3", mayo3);
//        parameters.put("mayo5", mayo5);
        parameters.put("MAYO_1", mayo1);
        parameters.put("MAYO_2", mayo2);
        parameters.put("MAYO_3", mayo3);
        parameters.put("MAYO_5", mayo5);
    }

    private final String name;

    private MayoParameterSpec(MayoParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static MayoParameterSpec fromName(String name)
    {
        return (MayoParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
