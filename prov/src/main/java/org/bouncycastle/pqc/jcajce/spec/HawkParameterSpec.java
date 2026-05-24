package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.util.Strings;

/**
 * {@link AlgorithmParameterSpec} for the Hawk PQC signature scheme. One
 * constant per supported parameter set ({@link #hawk_256}, {@link #hawk_512},
 * {@link #hawk_1024}); {@link #fromName(String)} looks up a spec by its
 * canonical lowercase name (case-insensitive) for use with
 * {@code Signature.getInstance(name, "BCPQC")} and
 * {@code KeyPairGenerator.getInstance(name, "BCPQC")}.
 */
public class HawkParameterSpec
    implements AlgorithmParameterSpec
{
    public static final HawkParameterSpec hawk_256 = new HawkParameterSpec(HawkParameters.Hawk_256);
    public static final HawkParameterSpec hawk_512 = new HawkParameterSpec(HawkParameters.Hawk_512);
    public static final HawkParameterSpec hawk_1024 = new HawkParameterSpec(HawkParameters.Hawk_1024);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("hawk-256", hawk_256);
        parameters.put("hawk-512", hawk_512);
        parameters.put("hawk-1024", hawk_1024);
    }

    private final String name;

    private HawkParameterSpec(HawkParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static HawkParameterSpec fromName(String name)
    {
        return (HawkParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
