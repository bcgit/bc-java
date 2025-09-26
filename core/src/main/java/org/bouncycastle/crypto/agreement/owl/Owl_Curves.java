package org.example;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;

/**
 * Standard pre-computed elliptic curves for use by Owl.
 * (Owl can use pre-computed elliptic curves or prime order groups, same as DSA and Diffie-Hellman.)
 * <p>
 * This class contains some convenient constants for use as input for
 * constructing {@link Owl_Client}s and {@link Owl_Server}.
 * <p>
 * The prime order groups below are taken from NIST SP 800-186,
 * "Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters",
 * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">published by NIST</a>.
 */
public class Owl_Curves
{
    /**
     * From NIST.
     * 128-bit security.
     */
    public static final Owl_Curve NIST_P256;

    /**
     * From NIST.
     * 192-bit security.
     */
    public static final Owl_Curve NIST_P384;

    /**
     * From NIST.
     * 256-bit security.
     */
    public static final Owl_Curve NIST_P521;

    static
    {
        NIST_P256 = getCurve("P-256");
        NIST_P384 = getCurve("P-384");
        NIST_P521 = getCurve("P-521");
    }

    private static Owl_Curve getCurve(String curveName)
    {
        X9ECParameters x9 = CustomNamedCurves.getByName(curveName);
        return new Owl_Curve((ECCurve.AbstractFp)x9.getCurve(), x9.getG());
    }
}