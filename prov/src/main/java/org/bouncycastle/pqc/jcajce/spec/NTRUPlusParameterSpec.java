package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.util.Strings;

public class NTRUPlusParameterSpec
    implements AlgorithmParameterSpec
{
    public static final NTRUPlusParameterSpec ntruplus_768 = new NTRUPlusParameterSpec(NTRUPlusParameters.ntruplus_kem_768);
    public static final NTRUPlusParameterSpec ntruplus_864 = new NTRUPlusParameterSpec(NTRUPlusParameters.ntruplus_kem_864);
    public static final NTRUPlusParameterSpec ntruplus_1152 = new NTRUPlusParameterSpec(NTRUPlusParameters.ntruplus_kem_1152);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("ntruplus-768", ntruplus_768);
        parameters.put("ntruplus-864", ntruplus_864);
        parameters.put("ntruplus-864", ntruplus_864);
    }

    private final String name;

    private NTRUPlusParameterSpec(NTRUPlusParameters parameters)
    {
        this.name = Strings.toUpperCase(parameters.getName());
    }

    public String getName()
    {
        return name;
    }

    public static NTRUPlusParameterSpec fromName(String name)
    {
        return (NTRUPlusParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}