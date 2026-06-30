package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.aimer.AIMerParameters;
import org.bouncycastle.util.Strings;

public class AIMerParameterSpec
    implements AlgorithmParameterSpec
{
    public static final AIMerParameterSpec aimer128f = new AIMerParameterSpec(AIMerParameters.aimer128f);
    public static final AIMerParameterSpec aimer128s = new AIMerParameterSpec(AIMerParameters.aimer128s);
    public static final AIMerParameterSpec aimer192f = new AIMerParameterSpec(AIMerParameters.aimer192f);
    public static final AIMerParameterSpec aimer192s = new AIMerParameterSpec(AIMerParameters.aimer192s);
    public static final AIMerParameterSpec aimer256f = new AIMerParameterSpec(AIMerParameters.aimer256f);
    public static final AIMerParameterSpec aimer256s = new AIMerParameterSpec(AIMerParameters.aimer256s);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("aimer128f", aimer128f);
        parameters.put("aimer128s", aimer128s);
        parameters.put("aimer192f", aimer192f);
        parameters.put("aimer192s", aimer192s);
        parameters.put("aimer256f", aimer256f);
        parameters.put("aimer256s", aimer256s);
    }

    private final String name;

    private AIMerParameterSpec(AIMerParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static AIMerParameterSpec fromName(String name)
    {
        return (AIMerParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
