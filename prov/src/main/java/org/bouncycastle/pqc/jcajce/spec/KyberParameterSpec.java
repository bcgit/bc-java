package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.util.Strings;

public class KyberParameterSpec
    implements AlgorithmParameterSpec
{
    public static final KyberParameterSpec kyber512 = new KyberParameterSpec(KyberParameters.kyber512);
    public static final KyberParameterSpec kyber768 = new KyberParameterSpec(KyberParameters.kyber768);
    public static final KyberParameterSpec kyber1024 = new KyberParameterSpec(KyberParameters.kyber1024);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("kyber512", kyber512);
        parameters.put("kyber768", kyber768);
        parameters.put("kyber1024", kyber1024);
    }

    private final String name;

    private KyberParameterSpec(KyberParameters parameters)
    {
        this.name = Strings.toUpperCase(parameters.getName());
    }

    public String getName()
    {
        return name;
    }

    public static KyberParameterSpec fromName(String name)
    {
        return (KyberParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
