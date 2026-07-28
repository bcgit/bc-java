package org.bouncycastle.math.ec;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Nat;

/**
 * Scalar multiplication of a variable point by a secret scalar, without leaking the scalar
 * through control flow or memory-access pattern.
 * <p>
 * {@link WNafL2RMultiplier} - the default multiplier for most curves - is not suitable for a
 * secret scalar: it selects between two precomputed tables on the sign of a wNAF digit, indexes
 * those tables directly with the digit's magnitude, and performs a run of doublings whose length
 * is the number of zeros in the recoding. All three depend on the scalar.
 * {@link FixedPointCombMultiplier} is constant-time but fixed-base only, and its precomputation
 * is far too expensive to pay per call on the varying point of a key agreement.
 * <p>
 * This multiplier uses a fixed window instead:
 * <ul>
 * <li>the scalar is forced odd (by adding the group order, which is odd, under a mask) and
 *     recoded into a fixed number of <em>odd</em> signed digits, so no digit is zero, and both
 *     the iteration count and the number of doublings are independent of the scalar;</li>
 * <li>the precomputed table holds the odd multiples and their negations, so a digit's sign is
 *     folded into its table index and no conditional point negation is needed;</li>
 * <li>table entries are fetched with {@link ECLookupTable#lookup(int)}, which
 *     {@link ECCurve#createCacheSafeLookupTable(ECPoint[], int, int)} implements as a masked scan
 *     over the whole table, so the index does not steer a memory access.</li>
 * </ul>
 * The result is identical to the other multipliers; only the timing profile differs. Expect it to
 * be somewhat slower, and markedly slower on a curve with a GLV endomorphism (secp256k1), whose
 * speedup is deliberately given up here - splitting the scalar for GLV is itself a
 * {@link BigInteger} computation on the secret.
 * <p>
 * The point must lie in the subgroup of the given order: forcing the scalar odd computes
 * <code>(k + n)P</code> in place of an even <code>kP</code>, and the two agree exactly when the
 * order of <code>P</code> divides <code>n</code>. Points validated against domain parameters
 * satisfy this ({@link ECPoint#isValid()} includes the order check); a point decoded straight off
 * the wire on a cofactor curve need not, and for such a point the result differs from
 * {@link ECPoint#multiply(BigInteger)} by <code>nP</code> on even scalars. For the same reason the
 * order must be odd - true of every standard EC group order, and enforced here, since an even one
 * would break the recoding silently.
 * <p>
 * NOTE: every step below is written to avoid branching on, or indexing with, the scalar. Do not
 * "simplify" the masked selections into conditionals. This class addresses the point arithmetic
 * only; a caller whose scalar arrives as a {@link BigInteger} still exposes that value's
 * magnitude through the length of its internal representation, and reduction of the scalar
 * before it reaches here (for example a cofactor adjustment) is outside the guarantee. The
 * guarantee also stops at the field layer: on the custom curves the field arithmetic is
 * fixed-length limb arithmetic, but on a generic {@link ECCurve.Fp} or F2m curve - brainpool,
 * the GOST curves, or a caller-built curve - the field operations under the point arithmetic
 * are {@link BigInteger}-based and their timing can vary with operand values.
 *
 * @see ECAlgorithms#multiplySecret(ECPoint, BigInteger)
 */
public class ECConstantTimeMultiplier
    extends AbstractECMultiplier
{
    private final BigInteger order;

    /**
     * Take the group order from the curve. Every curve in {@code ECNamedCurveTable} and
     * {@code CustomNamedCurves} carries one, but a caller-built {@link ECCurve} need not - see
     * {@link #ECConstantTimeMultiplier(BigInteger)}.
     */
    public ECConstantTimeMultiplier()
    {
        this(null);
    }

    /**
     * @param order the group order, or null to take it from the curve; must be odd. The recoding
     *              needs the order to force the scalar odd, and {@link ECCurve#getOrder()} is null
     *              for a curve built without one - domain parameters always carry it separately,
     *              so a caller that has {@code ECDomainParameters} should pass its {@code getN()}.
     */
    public ECConstantTimeMultiplier(BigInteger order)
    {
        this.order = order;
    }

    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECCurve c = p.getCurve();

        BigInteger order = this.order != null ? this.order : c.getOrder();
        if (order == null)
        {
            throw new IllegalStateException("constant-time multiplier requires a known group order");
        }
        if (!order.testBit(0))
        {
            throw new IllegalStateException("constant-time multiplier requires an odd group order");
        }
        if (k.bitLength() > order.bitLength())
        {
            throw new IllegalStateException("constant-time multiplier doesn't support scalars larger than the curve order");
        }

        int width = getWidth(order.bitLength());

        /*
         * One bit of headroom above the order, so that the odd-scalar adjustment below cannot
         * overflow: k < order, therefore k + order < 2 * order.
         */
        int size = order.bitLength() + 1;
        int len = (size + 31) >>> 5;
        int bits = len << 5;

        int[] K = Nat.fromBigInteger(bits, k);
        int[] N = Nat.fromBigInteger(bits, order);
        int[] KN = new int[len];
        Nat.add(len, K, N, KN);

        // the recoding needs an odd scalar; the order is odd, so k + order is odd when k is not
        int oddMask = -(K[0] & 1);
        for (int i = 0; i < len; ++i)
        {
            K[i] = (K[i] & oddMask) | (KN[i] & ~oddMask);
        }

        /*
         * Recode into 'd' odd digits in [-(2^width - 1), 2^width - 1]. Because K stays odd at
         * every step, no digit is zero and the final digit is positive - so the main loop below
         * always adds a real table entry and never has to handle the point at infinity.
         */
        int d = (size + width - 1) / width;
        int[] digits = new int[d];
        int lowMask = (1 << (width + 1)) - 1;
        int offset = 1 << width;

        for (int i = 0; i < d - 1; ++i)
        {
            int digit = (K[0] & lowMask) - offset;
            digits[i] = digit;

            addSigned(len, K, -digit);
            Nat.shiftDownBits(len, K, width, 0);
        }
        digits[d - 1] = K[0];

        int half = 1 << (width - 1);
        ECPoint[] table = new ECPoint[half << 1];

        // [1]P, [3]P, ... , [2^width - 1]P
        table[0] = p;
        if (half > 1)
        {
            ECPoint twoP = p.twice();
            for (int i = 1; i < half; ++i)
            {
                table[i] = table[i - 1].add(twoP);
            }
        }

        // the lookup table is built from the raw coordinates, so the points must be affine first
        c.normalizeAll(table, 0, half, null);

        for (int i = 0; i < half; ++i)
        {
            table[half + i] = table[i].negate();
        }

        ECLookupTable lookupTable = c.createCacheSafeLookupTable(table, 0, table.length);

        ECPoint R = lookupTable.lookup(lookupIndex(digits[d - 1], width));

        for (int i = d - 2; i >= 0; --i)
        {
            R = R.timesPow2(width);
            R = R.add(lookupTable.lookup(lookupIndex(digits[i], width)));
        }

        return R;
    }

    /**
     * Table index for a signed odd digit: the magnitude selects among the odd multiples and the
     * sign selects the negated half, so no conditional negation is needed.
     */
    private static int lookupIndex(int digit, int width)
    {
        int sign = digit >> 31;             // 0 or -1
        int abs = (digit ^ sign) - sign;

        return (abs >>> 1) | ((sign & 1) << (width - 1));
    }

    /**
     * z += v, where v is a signed 32-bit value sign-extended across z. Used to clear the low
     * digit before shifting; the caller guarantees the result stays non-negative.
     */
    private static void addSigned(int len, int[] z, int v)
    {
        long ext = (v >> 31) & 0xFFFFFFFFL;
        long cc = (z[0] & 0xFFFFFFFFL) + (v & 0xFFFFFFFFL);
        z[0] = (int)cc;
        cc >>>= 32;

        for (int i = 1; i < len; ++i)
        {
            cc += (z[i] & 0xFFFFFFFFL) + ext;
            z[i] = (int)cc;
            cc >>>= 32;
        }
    }

    /**
     * Window width. The table costs 2^(width-1) point additions to build and the main loop runs
     * ceil(size / width) iterations, so the useful range is narrow; these follow the same shape
     * as the widths {@link WNafUtil} picks for comparable scalar sizes.
     */
    protected int getWidth(int size)
    {
        if (size >= 384)
        {
            return 6;
        }
        if (size >= 192)
        {
            return 5;
        }
        return 4;
    }
}
