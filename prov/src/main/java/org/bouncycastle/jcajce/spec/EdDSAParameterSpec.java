package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * ParameterSpec for EdDSA signature algorithms.
 */
public class EdDSAParameterSpec
    implements AlgorithmParameterSpec
{
    public static final String Ed25519 = "Ed25519";
    public static final String Ed448 = "Ed448";

    private final String curveName;

    /**
     * Base constructor.
     *
     * @param curveName name of the curve to specify.
     */
    public EdDSAParameterSpec(String curveName)
    {
        if (!curveName.equals(Ed25519) && !curveName.equals(Ed448))
        {
            throw new IllegalArgumentException("unrecognized curve name: " + curveName);
        }
        this.curveName = curveName;
    }

    /**
     * Return the curve name specified by this parameterSpec.
     *
     * @return the name of the curve this parameterSpec specifies.
     */
    public String getCurveName()
    {
        return curveName;
    }
}
