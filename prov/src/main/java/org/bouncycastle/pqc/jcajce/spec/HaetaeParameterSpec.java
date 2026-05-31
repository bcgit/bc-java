package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.haetae.HAETAEParameters;
import org.bouncycastle.util.Strings;

/**
 * {@link AlgorithmParameterSpec} for the HAETAE PQC signature scheme (KpqC).
 * One constant per supported parameter set ({@link #haetae2}, {@link #haetae3},
 * {@link #haetae5}); {@link #fromName(String)} looks up a spec by its
 * canonical name (case-insensitive) for use with
 * {@code Signature.getInstance(name, "BCPQC")} and
 * {@code KeyPairGenerator.getInstance(name, "BCPQC")}.
 */
public class HaetaeParameterSpec
    implements AlgorithmParameterSpec
{
    public static final HaetaeParameterSpec haetae2 = new HaetaeParameterSpec(HAETAEParameters.haetae2);
    public static final HaetaeParameterSpec haetae3 = new HaetaeParameterSpec(HAETAEParameters.haetae3);
    public static final HaetaeParameterSpec haetae5 = new HaetaeParameterSpec(HAETAEParameters.haetae5);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("haetae-2", haetae2);
        parameters.put("haetae-3", haetae3);
        parameters.put("haetae-5", haetae5);
    }

    private final String name;

    private HaetaeParameterSpec(HAETAEParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static HaetaeParameterSpec fromName(String name)
    {
        return (HaetaeParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
