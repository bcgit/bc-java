package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.gm.SM9P256V1Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Fixed system parameters of the SM9 256-bit BN curve (GM/T 0044.5-2016, clause 1).
 * <p>
 * Curve E: y^2 = x^3 + 5 over F_q. G1 is the prime-order subgroup of E(F_q) with
 * generator P1; G2 is the subgroup of the sextic twist E'(F_p2): y^2 = x^3 + 5u
 * with generator P2. The R-ate pairing e: G1 x G2 -&gt; G_T uses loop parameter 6t+2.
 */
public class SM9Curve
{
    public static final BigInteger N = new BigInteger(
        "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25", 16);

    // BN parameter t and the R-ate Miller loop constant 6t+2 (GM/T 0044.5).
    static final BigInteger T = new BigInteger("600000000058F98A", 16);
    static final BigInteger LOOP = T.multiply(BigInteger.valueOf(6)).add(BigInteger.valueOf(2));

    // G1: E: y^2 = x^3 + 5 over F_q, backed by the constant-time Montgomery custom
    // curve (fixed-limb Nat256 field) rather than the generic BigInteger ECCurve.Fp.
    public static final ECCurve G1 = new SM9P256V1Curve();

    public static final ECPoint P1 = G1.createPoint(
        new BigInteger("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16),
        new BigInteger("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16));

    // twist constant b' = 5u  (F_p2 element with constant 0, u-coefficient 5)
//    static final Fp2 B_TWIST = new Fp2(ECConstants.ZERO, BigInteger.valueOf(5));

    // G2 generator P2. Each F_p2 coordinate is (constant, u-coefficient); the
    // standard prints the u-coefficient (high dim) first.
    public static final SM9G2Point P2 = new SM9G2Point(
        new Fp2(new BigInteger("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B", 16),
                new BigInteger("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141", 16)),
        new Fp2(new BigInteger("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7", 16),
                new BigInteger("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96", 16)));

    /**
     * Encode a G1 point as x || y (32 bytes each, big-endian), the affine-coordinate
     * form SM9 concatenates into KDF/MAC inputs and ciphertexts (no 0x04 prefix).
     */
    public static byte[] g1ToBytes(ECPoint p)
    {
        ECPoint n = p.normalize();
        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(32, n.getAffineXCoord().toBigInteger()),
            BigIntegers.asUnsignedByteArray(32, n.getAffineYCoord().toBigInteger()));
    }

    /**
     * Reconstruct a G1 point from its 64-byte x || y encoding. The caller is
     * responsible for validating the result (e.g. {@link ECPoint#isValid()}).
     */
    public static ECPoint g1FromBytes(byte[] b, int off)
    {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(b, off, off + 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(b, off + 32, off + 64));
        return G1.createPoint(x, y);
    }

    // A fixed-point comb multiplier: a fixed number of iterations with a cache-safe
    // (constant-time) table lookup - the same multiplier BouncyCastle's ECDSA/SM2
    // use for the secret nonce times the base point. Stateless, so a single shared
    // instance is safe.
    private static final FixedPointCombMultiplier G1_SECURE_MULTIPLIER = new FixedPointCombMultiplier();

    /**
     * Constant-time G1 scalar multiplication for <b>secret</b> scalars, used for
     * every SM9 scalar multiplication by private key material or an ephemeral
     * secret (whether the base is the fixed generator P1 or a variable point such
     * as a user's private-key point or a recipient point). The comb runs a fixed
     * number of steps and reads its precomputed table in constant time, so the
     * number and pattern of point operations do not depend on the scalar - unlike
     * the default windowed-NAF multiplier that {@link ECPoint#multiply} would use.
     * <p>
     * NOTE: G1 is backed by the fixed-limb Montgomery field
     * {@link org.bouncycastle.math.ec.custom.gm.SM9P256V1Field}, so its field
     * arithmetic is constant time; the residual variable-time cost is only the
     * final conditional subtract / carry normalisation, as in BouncyCastle's other
     * custom prime-field curves.
     */
    public static ECPoint multiplySecure(ECPoint p, BigInteger k)
    {
        return G1_SECURE_MULTIPLIER.multiply(p, k);
    }

    private SM9Curve()
    {
    }
}
