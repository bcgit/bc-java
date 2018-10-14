package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

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
        if (curveName.equalsIgnoreCase(Ed25519))
        {
            this.curveName = Ed25519;
        }
        else if (curveName.equalsIgnoreCase(Ed448))
        {
            this.curveName = Ed448;
        }
        else if (curveName.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
        {
            this.curveName = Ed25519;
        }
        else if (curveName.equals(EdECObjectIdentifiers.id_Ed448.getId()))
        {
            this.curveName = Ed448;
        }
        else
        {
            throw new IllegalArgumentException("unrecognized curve name: " + curveName);
        }

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
