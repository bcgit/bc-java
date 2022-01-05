package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.util.Strings;

public class CMCEParameterSpec
    implements AlgorithmParameterSpec
{
    public static final CMCEParameterSpec mceliece348864 = new CMCEParameterSpec(CMCEParameters.mceliece348864);
    public static final CMCEParameterSpec mceliece348864f = new CMCEParameterSpec(CMCEParameters.mceliece348864f);
    public static final CMCEParameterSpec mceliece460896 = new CMCEParameterSpec(CMCEParameters.mceliece460896);
    public static final CMCEParameterSpec mceliece460896f = new CMCEParameterSpec(CMCEParameters.mceliece460896f);
    public static final CMCEParameterSpec mceliece6688128 = new CMCEParameterSpec(CMCEParameters.mceliece6688128);
    public static final CMCEParameterSpec mceliece6688128f = new CMCEParameterSpec(CMCEParameters.mceliece6688128f);
    public static final CMCEParameterSpec mceliece6960119 = new CMCEParameterSpec(CMCEParameters.mceliece6960119);
    public static final CMCEParameterSpec mceliece6960119f = new CMCEParameterSpec(CMCEParameters.mceliece6960119f);
    public static final CMCEParameterSpec mceliece8192128 = new CMCEParameterSpec(CMCEParameters.mceliece8192128);
    public static final CMCEParameterSpec mceliece8192128f = new CMCEParameterSpec(CMCEParameters.mceliece8192128f);

    private static Map parameters = new HashMap();

    static
    {

    }

    private final String name;

    private CMCEParameterSpec(CMCEParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static CMCEParameterSpec fromName(String name)
    {
        return (CMCEParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
