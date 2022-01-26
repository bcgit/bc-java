package org.bouncycastle.pqc.jcajce.spec;

import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.util.Strings;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SABERParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SABERParameterSpec lightsaberkemr3 = new SABERParameterSpec(SABERParameters.lightsaberkemr3);
    public static final SABERParameterSpec saberkemr3 = new SABERParameterSpec(SABERParameters.saberkemr3);
    public static final SABERParameterSpec firesaberkemr3 = new SABERParameterSpec(SABERParameters.firesaberkemr3);

    private static Map parameters = new HashMap();

    private final String name;

    private SABERParameterSpec(SABERParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }
    public static SABERParameterSpec fromName(String name)
    {
        return (SABERParameterSpec) parameters.get(Strings.toLowerCase(name));
    }
}
