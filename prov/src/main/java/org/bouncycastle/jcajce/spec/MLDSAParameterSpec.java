package org.bouncycastle.jcajce.spec;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.util.Strings;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

/**
 * AlgorithmSpec for ML-DSA
 */
public class MLDSAParameterSpec
    implements AlgorithmParameterSpec
{
    public static final MLDSAParameterSpec ml_dsa_44 = new MLDSAParameterSpec("ML-DSA-44");
    public static final MLDSAParameterSpec ml_dsa_65 = new MLDSAParameterSpec("ML-DSA-65");
    public static final MLDSAParameterSpec ml_dsa_87 = new MLDSAParameterSpec("ML-DSA-87");


    private static Map parameters = new HashMap();

    static
    {
        parameters.put("ML-DSA-44", MLDSAParameterSpec.ml_dsa_44);
        parameters.put("ML-DSA-65", MLDSAParameterSpec.ml_dsa_65);
        parameters.put("ML-DSA-87", MLDSAParameterSpec.ml_dsa_87);

        parameters.put("dilithium2", MLDSAParameterSpec.ml_dsa_44);
        parameters.put("dilithium3", MLDSAParameterSpec.ml_dsa_65);
        parameters.put("dilithium5", MLDSAParameterSpec.ml_dsa_87);
    }

    private final String name;

    private MLDSAParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }
    
    public static MLDSAParameterSpec fromName(String name)
    {
        return (MLDSAParameterSpec)parameters.get(name);
    }
}
