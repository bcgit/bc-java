package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Curve parameters for BLS12-381 G1, the prime-order subgroup of {@code E(Fp)}
 * defined by {@code y^2 = x^3 + 4} over {@code Fp}, as standardised in
 * draft-irtf-cfrg-bls-signature and RFC 9380 sec. 8.8.1.
 * <p>
 * The curve is exposed via the standard {@link ECCurve.Fp} (BigInteger-backed)
 * so that hash-to-curve and other G1-only consumers can be built on top
 * without depending on a custom limb-array representation.
 */
public class BLS12_381G1
{
    /** Base field characteristic p. 381 bits. */
    public static final BigInteger Q = new BigInteger(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
        16);

    /** G1 prime-order subgroup order r. 255 bits. */
    public static final BigInteger ORDER = new BigInteger(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    /** G1 cofactor h. */
    public static final BigInteger COFACTOR = new BigInteger(
        "396c8c005555e1568c00aaab0000aaab", 16);

    /**
     * Effective cofactor for hash-to-curve (RFC 9380 sec. 8.8.1):
     * {@code h_eff = 1 - x} where {@code x = -0xd201000000010000} is the
     * BLS12-381 trace parameter, so {@code h_eff = 0xd201000000010001}.
     * Multiplying any point on E(Fp) by h_eff lands in the prime-order
     * subgroup; this is faster than the full cofactor multiplication and is
     * the form mandated by the hash-to-curve suite.
     */
    public static final BigInteger H_EFF = new BigInteger("d201000000010001", 16);

    /** Generator x-coordinate. */
    private static final BigInteger GX = new BigInteger(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        16);

    /** Generator y-coordinate. */
    private static final BigInteger GY = new BigInteger(
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
        16);

    private BLS12_381G1()
    {
    }

    /**
     * @return a fresh {@link ECCurve} instance for BLS12-381 G1
     * ({@code y^2 = x^3 + 4} over Fp). Each call returns an independent
     * curve; consumers that build derived structures (auxiliary isogeny
     * curves, lookup tables, etc.) should reuse one instance.
     */
    public static ECCurve createCurve()
    {
        return new ECCurve.Fp(Q, BigInteger.ZERO, BigInteger.valueOf(4), ORDER, COFACTOR);
    }

    /**
     * @return the standard generator G1 of the prime-order subgroup, on the
     * given curve instance (must be an instance returned by
     * {@link #createCurve()}).
     */
    public static ECPoint getGenerator(ECCurve curve)
    {
        return curve.createPoint(GX, GY);
    }

    /**
     * Constant-time scalar multiplication on G1, suitable for secret
     * scalars (e.g. {@code sk * G1_gen} in {@code skToPk}).
     * <p>
     * Same approach as {@link BLS12_381G2Point#constantTimeMultiply}: a
     * fixed-iteration "double, conditionally add" ladder over 256 bits
     * with an array-indexed select replacing the bit-conditional
     * {@code if}. Same caveats apply — the underlying BC ECPoint
     * arithmetic still has data-dependent branches for infinity / equal-x
     * cases (negligibly probable for random secret scalars on a
     * prime-order subgroup), and JVM-level timing variance is not
     * addressable in pure Java.
     */
    public static ECPoint constantTimeMultiply(ECPoint p, BigInteger scalar)
    {
        if (scalar == null)
        {
            throw new IllegalArgumentException("scalar must not be null");
        }
        if (scalar.signum() < 0)
        {
            return constantTimeMultiply(p.negate(), scalar.negate());
        }
        if (p.isInfinity())
        {
            return p.getCurve().getInfinity();
        }

        final int FIXED_BITS = 256;
        ECPoint r = p.getCurve().getInfinity();
        ECPoint[] options = new ECPoint[2];
        for (int i = FIXED_BITS - 1; i >= 0; --i)
        {
            r = r.twice();
            ECPoint candidate = r.add(p);
            options[0] = r;
            options[1] = candidate;
            int bit = scalar.testBit(i) ? 1 : 0;
            r = options[bit];
        }
        return r.normalize();
    }
}
