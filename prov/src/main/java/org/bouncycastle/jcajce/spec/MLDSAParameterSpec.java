package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmSpec for ML-DSA
 */
public class MLDSAParameterSpec
    implements AlgorithmParameterSpec
{
    public static final MLDSAParameterSpec ml_dsa_44 = new MLDSAParameterSpec("ml-dsa-44");
    public static final MLDSAParameterSpec ml_dsa_65 = new MLDSAParameterSpec("ml-dsa-65");
    public static final MLDSAParameterSpec ml_dsa_87 = new MLDSAParameterSpec("ml-dsa-87");

    public static final MLDSAParameterSpec ml_dsa_44_with_sha512 = new MLDSAParameterSpec("ml-dsa-44-with-sha512");
    public static final MLDSAParameterSpec ml_dsa_65_with_sha512 = new MLDSAParameterSpec("ml-dsa-65-with-sha512");
    public static final MLDSAParameterSpec ml_dsa_87_with_sha512 = new MLDSAParameterSpec("ml-dsa-87-with-sha512");

    private static Map parameters = new HashMap();

    static
    {
        parameters.put(ml_dsa_44.name, MLDSAParameterSpec.ml_dsa_44);
        parameters.put(ml_dsa_65.name, MLDSAParameterSpec.ml_dsa_65);
        parameters.put(ml_dsa_87.name, MLDSAParameterSpec.ml_dsa_87);
        parameters.put(ml_dsa_44_with_sha512.name, MLDSAParameterSpec.ml_dsa_44_with_sha512);
        parameters.put(ml_dsa_65_with_sha512.name, MLDSAParameterSpec.ml_dsa_65_with_sha512);
        parameters.put(ml_dsa_87_with_sha512.name, MLDSAParameterSpec.ml_dsa_87_with_sha512);
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
        return (MLDSAParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
