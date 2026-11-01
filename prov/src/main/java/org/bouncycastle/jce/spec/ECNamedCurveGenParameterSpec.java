package org.bouncycastle.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

/**
 * Named curve generation spec
 * <p>
 * If you are using JDK 1.5 you should be looking at ECGenParameterSpec.
 */
public class ECNamedCurveGenParameterSpec
    implements AlgorithmParameterSpec
{
    private String  name;

    public ECNamedCurveGenParameterSpec(
        String name)
    {
        this.name = name;
    }

    /**
     * return the name of the curve the EC domain parameters belong to.
     */
    public String getName()
    {
        return name;
    }

    /**
     * Return the curve name and its OID, for example "secp384r1 (1.3.132.0.34)".
     */
    public String toString()
    {
        return String.valueOf(ECUtil.namedCurveToString(name));
    }
}
