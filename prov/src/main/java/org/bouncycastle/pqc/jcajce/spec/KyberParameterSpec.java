package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.util.Strings;

public class KyberParameterSpec
    implements AlgorithmParameterSpec
{
    public static final KyberParameterSpec kyber512 = new KyberParameterSpec(MLKEMParameters.ml_kem_512);
    public static final KyberParameterSpec kyber768 = new KyberParameterSpec(MLKEMParameters.ml_kem_768);
    public static final KyberParameterSpec kyber1024 = new KyberParameterSpec(MLKEMParameters.ml_kem_1024);

    private static Map parameters = new HashMap();

    static
    {
        // getName() returns the ML-KEM name (e.g. "ML-KEM-512"), so it must be a key
        // for fromName(getName()) to round-trip; the legacy "kyber*" names are kept as
        // aliases. Mirrors org.bouncycastle.jcajce.spec.MLKEMParameterSpec.
        parameters.put("ml-kem-512", kyber512);
        parameters.put("ml-kem-768", kyber768);
        parameters.put("ml-kem-1024", kyber1024);

        parameters.put("kyber512", kyber512);
        parameters.put("kyber768", kyber768);
        parameters.put("kyber1024", kyber1024);
    }

    private final String name;

    private KyberParameterSpec(MLKEMParameters parameters)
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
