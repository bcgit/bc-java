package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.faest.FaestParameters;
import org.bouncycastle.util.Strings;

public class FaestParameterSpec
    implements AlgorithmParameterSpec
{
    public static final FaestParameterSpec faest_128s = new FaestParameterSpec(FaestParameters.faest_128s);
    public static final FaestParameterSpec faest_128f = new FaestParameterSpec(FaestParameters.faest_128f);
    public static final FaestParameterSpec faest_192s = new FaestParameterSpec(FaestParameters.faest_192s);
    public static final FaestParameterSpec faest_192f = new FaestParameterSpec(FaestParameters.faest_192f);
    public static final FaestParameterSpec faest_256s = new FaestParameterSpec(FaestParameters.faest_256s);
    public static final FaestParameterSpec faest_256f = new FaestParameterSpec(FaestParameters.faest_256f);

    public static final FaestParameterSpec faest_em_128s = new FaestParameterSpec(FaestParameters.faest_em_128s);
    public static final FaestParameterSpec faest_em_128f = new FaestParameterSpec(FaestParameters.faest_em_128f);
    public static final FaestParameterSpec faest_em_192s = new FaestParameterSpec(FaestParameters.faest_em_192s);
    public static final FaestParameterSpec faest_em_192f = new FaestParameterSpec(FaestParameters.faest_em_192f);
    public static final FaestParameterSpec faest_em_256s = new FaestParameterSpec(FaestParameters.faest_em_256s);
    public static final FaestParameterSpec faest_em_256f = new FaestParameterSpec(FaestParameters.faest_em_256f);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("faest_128s", faest_128s);
        parameters.put("faest_128f", faest_128f);
        parameters.put("faest_192s", faest_192s);
        parameters.put("faest_192f", faest_192f);
        parameters.put("faest_256s", faest_256s);
        parameters.put("faest_256f", faest_256f);

        parameters.put("faest_em_128s", faest_em_128s);
        parameters.put("faest_em_128f", faest_em_128f);
        parameters.put("faest_em_192s", faest_em_192s);
        parameters.put("faest_em_192f", faest_em_192f);
        parameters.put("faest_em_256s", faest_em_256s);
        parameters.put("faest_em_256f", faest_em_256f);
    }

    private final String name;

    private FaestParameterSpec(FaestParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static FaestParameterSpec fromName(String name)
    {
        return (FaestParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
