package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.util.Strings;

public class SNTRUPrimeParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SNTRUPrimeParameterSpec sntrup653 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup653);
    public static final SNTRUPrimeParameterSpec sntrup761 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup761);
    public static final SNTRUPrimeParameterSpec sntrup857 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup857);
    public static final SNTRUPrimeParameterSpec sntrup953 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup953);
    public static final SNTRUPrimeParameterSpec sntrup1013 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup1013);
    public static final SNTRUPrimeParameterSpec sntrup1277 = new SNTRUPrimeParameterSpec(SNTRUPrimeParameters.sntrup1277);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("sntrup653", sntrup653);
        parameters.put("sntrup761", sntrup761);
        parameters.put("sntrup857", sntrup857);
        parameters.put("sntrup953", sntrup953);
        parameters.put("sntrup1013", sntrup1013);
        parameters.put("sntrup1277", sntrup1277);
    }

    private final String name;

    private SNTRUPrimeParameterSpec(SNTRUPrimeParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }
    public static SNTRUPrimeParameterSpec fromName(String name)
    {
        return (SNTRUPrimeParameterSpec) parameters.get(Strings.toLowerCase(name));
    }
}
