package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.mirath.MirathParameters;
import org.bouncycastle.util.Strings;

public class MirathParameterSpec
    implements AlgorithmParameterSpec
{
    public static final MirathParameterSpec Mirath_1a_fast = new MirathParameterSpec(MirathParameters.mirath_1a_fast);
    public static final MirathParameterSpec Mirath_1a_short = new MirathParameterSpec(MirathParameters.mirath_1a_short);
    public static final MirathParameterSpec Mirath_1b_fast = new MirathParameterSpec(MirathParameters.mirath_1b_fast);
    public static final MirathParameterSpec Mirath_1b_short = new MirathParameterSpec(MirathParameters.mirath_1b_short);
    public static final MirathParameterSpec Mirath_3a_fast = new MirathParameterSpec(MirathParameters.mirath_3a_fast);
    public static final MirathParameterSpec Mirath_3a_short = new MirathParameterSpec(MirathParameters.mirath_3a_short);
    public static final MirathParameterSpec Mirath_3b_fast = new MirathParameterSpec(MirathParameters.mirath_3b_fast);
    public static final MirathParameterSpec Mirath_3b_short = new MirathParameterSpec(MirathParameters.mirath_3b_short);
    public static final MirathParameterSpec Mirath_5a_fast = new MirathParameterSpec(MirathParameters.mirath_5a_fast);
    public static final MirathParameterSpec Mirath_5a_short = new MirathParameterSpec(MirathParameters.mirath_5a_short);
    public static final MirathParameterSpec Mirath_5b_fast = new MirathParameterSpec(MirathParameters.mirath_5b_fast);
    public static final MirathParameterSpec Mirath_5b_short = new MirathParameterSpec(MirathParameters.mirath_5b_short);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("Mirath_1a_fast", Mirath_1a_fast);
        parameters.put("Mirath_1a_short", Mirath_1a_short);
        parameters.put("Mirath_1b_fast", Mirath_1b_fast);
        parameters.put("Mirath_1b_short", Mirath_1b_short);
        parameters.put("Mirath_3a_fast", Mirath_3a_fast);
        parameters.put("Mirath_3a_short", Mirath_3a_short);
        parameters.put("Mirath_3b_fast", Mirath_3b_fast);
        parameters.put("Mirath_3b_short", Mirath_3b_short);
        parameters.put("Mirath_5a_fast", Mirath_5a_fast);
        parameters.put("Mirath_5a_short", Mirath_5a_short);
        parameters.put("Mirath_5b_fast", Mirath_5b_fast);
        parameters.put("Mirath_5b_short", Mirath_5b_short);
    }

    private final String name;

    private MirathParameterSpec(MirathParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static MirathParameterSpec fromName(String name)
    {
        return (MirathParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
