package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

/**
 * A DHPublicKeySpec that also carries a set of DH domain parameters.
 */
public class DHExtendedPublicKeySpec
    extends DHPublicKeySpec
{
    private final DHParameterSpec params;

    /**
     * Base constructor.
     *
     * @param y the public value.
     * @param params the domain parameter set.
     */
    public DHExtendedPublicKeySpec(BigInteger y, DHParameterSpec params)
    {
        super(y, params.getP(), params.getG());
        this.params = params;
    }

    /**
     * Return the domain parameters associated with this key spec.
     *
     * @return the Diffie-Hellman domain parameters.
     */
    public DHParameterSpec getParams()
    {
        return params;
    }
}
