package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.util.Strings;

public class SIKEParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SIKEParameterSpec sikep434 = new SIKEParameterSpec(SIKEParameters.sikep434);
    public static final SIKEParameterSpec sikep503 = new SIKEParameterSpec(SIKEParameters.sikep503);
    public static final SIKEParameterSpec sikep610 = new SIKEParameterSpec(SIKEParameters.sikep610);
    public static final SIKEParameterSpec sikep751 = new SIKEParameterSpec(SIKEParameters.sikep751);
    public static final SIKEParameterSpec sikep434_compressed = new SIKEParameterSpec(SIKEParameters.sikep434_compressed);
    public static final SIKEParameterSpec sikep503_compressed = new SIKEParameterSpec(SIKEParameters.sikep503_compressed);
    public static final SIKEParameterSpec sikep610_compressed = new SIKEParameterSpec(SIKEParameters.sikep610_compressed);
    public static final SIKEParameterSpec sikep751_compressed = new SIKEParameterSpec(SIKEParameters.sikep751_compressed);

    private static Map parameters = new HashMap();

    private final String name;

    private SIKEParameterSpec(SIKEParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }
    public static SIKEParameterSpec fromName(String name)
    {
        return (SIKEParameterSpec) parameters.get(Strings.toLowerCase(name));
    }
}
