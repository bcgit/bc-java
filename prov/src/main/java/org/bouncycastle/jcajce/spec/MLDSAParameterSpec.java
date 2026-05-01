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
    public static final MLDSAParameterSpec ml_dsa_44 = new MLDSAParameterSpec("ML-DSA-44");
    public static final MLDSAParameterSpec ml_dsa_65 = new MLDSAParameterSpec("ML-DSA-65");
    public static final MLDSAParameterSpec ml_dsa_87 = new MLDSAParameterSpec("ML-DSA-87");

    public static final MLDSAParameterSpec ml_dsa_44_with_sha512 = new MLDSAParameterSpec("ML-DSA-44-WITH-SHA512");
    public static final MLDSAParameterSpec ml_dsa_65_with_sha512 = new MLDSAParameterSpec("ML-DSA-65-WITH-SHA512");
    public static final MLDSAParameterSpec ml_dsa_87_with_sha512 = new MLDSAParameterSpec("ML-DSA-87-WITH-SHA512");

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("ml-dsa-44", MLDSAParameterSpec.ml_dsa_44);
        parameters.put("ml-dsa-65", MLDSAParameterSpec.ml_dsa_65);
        parameters.put("ml-dsa-87", MLDSAParameterSpec.ml_dsa_87);
        parameters.put("ml-dsa-44-with-sha512", MLDSAParameterSpec.ml_dsa_44_with_sha512);
        parameters.put("ml-dsa-65-with-sha512", MLDSAParameterSpec.ml_dsa_65_with_sha512);
        parameters.put("ml-dsa-87-with-sha512", MLDSAParameterSpec.ml_dsa_87_with_sha512);
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
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }

        MLDSAParameterSpec parameterSpec = (MLDSAParameterSpec)parameters.get(Strings.toLowerCase(name));

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }

        return parameterSpec;
    }
}
