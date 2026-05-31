package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.sqisign.SQIsignParameters;
import org.bouncycastle.util.Strings;

public class SQIsignParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SQIsignParameterSpec sqisign_lvl1 = new SQIsignParameterSpec(SQIsignParameters.sqisign_lvl1);
    public static final SQIsignParameterSpec sqisign_lvl3 = new SQIsignParameterSpec(SQIsignParameters.sqisign_lvl3);
    public static final SQIsignParameterSpec sqisign_lvl5 = new SQIsignParameterSpec(SQIsignParameters.sqisign_lvl5);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("sqisign_lvl1", sqisign_lvl1);
        parameters.put("sqisign_lvl3", sqisign_lvl3);
        parameters.put("sqisign_lvl5", sqisign_lvl5);
    }

    private final String name;

    private SQIsignParameterSpec(SQIsignParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static SQIsignParameterSpec fromName(String name)
    {
        if (name == null)
        {
            return null;
        }
        return (SQIsignParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
