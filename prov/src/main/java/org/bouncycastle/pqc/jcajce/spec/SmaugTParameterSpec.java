package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.smaugt.SmaugTParameters;
import org.bouncycastle.util.Strings;

public class SmaugTParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SmaugTParameterSpec smaugt_mode1 = new SmaugTParameterSpec(SmaugTParameters.smaugt_mode1);
    public static final SmaugTParameterSpec smaugt_mode3 = new SmaugTParameterSpec(SmaugTParameters.smaugt_mode3);
    public static final SmaugTParameterSpec smaugt_mode5 = new SmaugTParameterSpec(SmaugTParameters.smaugt_mode5);
    public static final SmaugTParameterSpec smaugt_modet = new SmaugTParameterSpec(SmaugTParameters.smaugt_modet);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("smaugt-mode1", smaugt_mode1);
        parameters.put("smaugt-mode3", smaugt_mode3);
        parameters.put("smaugt-mode5", smaugt_mode5);
        parameters.put("smaugt-modet", smaugt_modet);

        parameters.put("smaugt_mode1", smaugt_mode1);
        parameters.put("smaugt_mode3", smaugt_mode3);
        parameters.put("smaugt_mode5", smaugt_mode5);
        parameters.put("smaugt_modet", smaugt_modet);
    }

    private final String name;

    private SmaugTParameterSpec(SmaugTParameters parameters)
    {
        this.name = Strings.toUpperCase(parameters.getName());
    }

    public String getName()
    {
        return name;
    }

    public static SmaugTParameterSpec fromName(String name)
    {
        return (SmaugTParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
