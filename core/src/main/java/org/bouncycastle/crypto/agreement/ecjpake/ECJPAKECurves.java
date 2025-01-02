package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Standard pre-computed elliptic curves for use by EC J-PAKE.
 * (J-PAKE can use pre-computed elliptic curves or prime order groups, same as DSA and Diffie-Hellman.)
 * <p>
 * This class contains some convenient constants for use as input for
 * constructing {@link ECJPAKEParticipant}s.
 * <p>
 * The prime order groups below are taken from NIST SP 800-186,
 * "Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters",
 * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">published by NIST</a>.
 */
public class ECJPAKECurves
{

    /**
     * From NIST.
     * 128-bit security.
     */
    public static final ECJPAKECurve NIST_P256;

    static
    {
        //a
        BigInteger a_p256 = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
        //b
        BigInteger b_p256 = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
        //q
        BigInteger q_p256 = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
        //h
        BigInteger h_p256 = BigInteger.ONE;
        //n
        BigInteger n_p256 = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
        //g
        ECCurve.Fp curve_p256 = new ECCurve.Fp(q_p256, a_p256, b_p256, n_p256, h_p256);
        ECPoint g_p256 = curve_p256.createPoint(
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16));

        NIST_P256 = new ECJPAKECurve(a_p256, b_p256, q_p256, h_p256, n_p256, g_p256, curve_p256, true);
    }

    /**
     * From NIST.
     * 192-bit security.
     */
    public static final ECJPAKECurve NIST_P384;

    static
    {
        //a
        BigInteger a_p384 = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16);
        //b
        BigInteger b_p384 = new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);
        //q
        BigInteger q_p384 = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
        //h
        BigInteger h_p384 = BigInteger.ONE;
        //n
        BigInteger n_p384 = new BigInteger("ffffffffffffffffffffffffffffffffc7634d81581a0db248b0a77aecec196accc52973", 16);
        //g
        ECCurve.Fp curve_p384 = new ECCurve.Fp(q_p384, a_p384, b_p384, n_p384, h_p384);
        ECPoint g_p384 = curve_p384.createPoint(
            new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
            new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16));

        NIST_P384 = new ECJPAKECurve(a_p384, b_p384, q_p384, h_p384, n_p384, g_p384, curve_p384, true);
    }

    /**
     * From NIST.
     * 128-bit security.
     */
    public static final ECJPAKECurve NIST_P521;

    static
    {
        //a
        BigInteger a_p521 = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16);
        //b
        BigInteger b_p521 = new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);
        //q
        BigInteger q_p521 = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
        //h
        BigInteger h_p521 = BigInteger.ONE;
        //n
        BigInteger n_p521 = new BigInteger("ffffffffffffffffffffffffffffffffc7634d81581a0db248b0a77aecec196accc52973", 16);
        //g
        ECCurve.Fp curve_p521 = new ECCurve.Fp(q_p521, a_p521, b_p521, n_p521, h_p521);
        ECPoint g_p521 = curve_p521.createPoint(
            new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
            new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16));

        NIST_P521 = new ECJPAKECurve(a_p521, b_p521, q_p521, h_p521, n_p521, g_p521, curve_p521, true);
    }


}
