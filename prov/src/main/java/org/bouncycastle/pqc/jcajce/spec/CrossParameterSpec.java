package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.cross.CrossParameters;
import org.bouncycastle.util.Strings;

public class CrossParameterSpec
    implements AlgorithmParameterSpec
{
    public static final CrossParameterSpec cross_rsdp_1_small = new CrossParameterSpec(CrossParameters.cross_rsdp_1_small);
    public static final CrossParameterSpec cross_rsdp_1_balanced = new CrossParameterSpec(CrossParameters.cross_rsdp_1_balanced);
    public static final CrossParameterSpec cross_rsdp_1_fast = new CrossParameterSpec(CrossParameters.cross_rsdp_1_fast);

    public static final CrossParameterSpec cross_rsdp_3_small = new CrossParameterSpec(CrossParameters.cross_rsdp_3_small);
    public static final CrossParameterSpec cross_rsdp_3_balanced = new CrossParameterSpec(CrossParameters.cross_rsdp_3_balanced);
    public static final CrossParameterSpec cross_rsdp_3_fast = new CrossParameterSpec(CrossParameters.cross_rsdp_3_fast);

    public static final CrossParameterSpec cross_rsdp_5_small = new CrossParameterSpec(CrossParameters.cross_rsdp_5_small);
    public static final CrossParameterSpec cross_rsdp_5_balanced = new CrossParameterSpec(CrossParameters.cross_rsdp_5_balanced);
    public static final CrossParameterSpec cross_rsdp_5_fast = new CrossParameterSpec(CrossParameters.cross_rsdp_5_fast);

    public static final CrossParameterSpec cross_rsdpg_1_small = new CrossParameterSpec(CrossParameters.cross_rsdpg_1_small);
    public static final CrossParameterSpec cross_rsdpg_1_balanced = new CrossParameterSpec(CrossParameters.cross_rsdpg_1_balanced);
    public static final CrossParameterSpec cross_rsdpg_1_fast = new CrossParameterSpec(CrossParameters.cross_rsdpg_1_fast);

    public static final CrossParameterSpec cross_rsdpg_3_small = new CrossParameterSpec(CrossParameters.cross_rsdpg_3_small);
    public static final CrossParameterSpec cross_rsdpg_3_balanced = new CrossParameterSpec(CrossParameters.cross_rsdpg_3_balanced);
    public static final CrossParameterSpec cross_rsdpg_3_fast = new CrossParameterSpec(CrossParameters.cross_rsdpg_3_fast);

    public static final CrossParameterSpec cross_rsdpg_5_small = new CrossParameterSpec(CrossParameters.cross_rsdpg_5_small);
    public static final CrossParameterSpec cross_rsdpg_5_balanced = new CrossParameterSpec(CrossParameters.cross_rsdpg_5_balanced);
    public static final CrossParameterSpec cross_rsdpg_5_fast = new CrossParameterSpec(CrossParameters.cross_rsdpg_5_fast);


    private static Map parameters = new HashMap();

    static
    {
        parameters.put("Cross-RSDP-1-SMALL", cross_rsdp_1_small);
        parameters.put("Cross-RSDP-1-BALANCED", cross_rsdp_1_balanced);
        parameters.put("Cross-RSDP-1-FAST", cross_rsdp_1_fast);

        parameters.put("Cross-RSDP-3-SMALL", cross_rsdp_3_small);
        parameters.put("Cross-RSDP-3-BALANCED", cross_rsdp_3_balanced);
        parameters.put("Cross-RSDP-3-FAST", cross_rsdp_3_fast);

        parameters.put("Cross-RSDP-5-SMALL", cross_rsdp_5_small);
        parameters.put("Cross-RSDP-5-BALANCED", cross_rsdp_5_balanced);
        parameters.put("Cross-RSDP-5-FAST", cross_rsdp_5_fast);

        parameters.put("Cross-RSDPG-1-SMALL", cross_rsdpg_1_small);
        parameters.put("Cross-RSDPG-1-BALANCED", cross_rsdpg_1_balanced);
        parameters.put("Cross-RSDPG-1-FAST", cross_rsdpg_1_fast);

        parameters.put("Cross-RSDPG-3-SMALL", cross_rsdpg_3_small);
        parameters.put("Cross-RSDPG-3-BALANCED", cross_rsdpg_3_balanced);
        parameters.put("Cross-RSDPG-3-FAST", cross_rsdpg_3_fast);

        parameters.put("Cross-RSDPG-5-SMALL", cross_rsdpg_5_small);
        parameters.put("Cross-RSDPG-5-BALANCED", cross_rsdpg_5_balanced);
        parameters.put("Cross-RSDPG-5-FAST", cross_rsdpg_5_fast);
    }

    private final String name;

    private CrossParameterSpec(CrossParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static CrossParameterSpec fromName(String name)
    {
        return (CrossParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
