package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * ParameterSpec for XDH key agreement algorithms.
 */
public class XDHParameterSpec
    implements AlgorithmParameterSpec
{
    public static final String X25519 = "X25519";
    public static final String X448 = "X448";

    private final String curveName;

    /**
     * Base constructor.
     *
     * @param curveName name of the curve to specify.
     */
    public XDHParameterSpec(String curveName)
    {
        if (!curveName.equals(X25519) && !curveName.equals(X448))
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
