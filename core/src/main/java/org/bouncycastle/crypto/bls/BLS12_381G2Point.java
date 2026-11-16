package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

/**
 * Affine point on the BLS12-381 G2 curve {@code E: y^2 = x^3 + 4*(1+I)} over
 * Fp^2.
 * <p>
 * Points are held in affine coordinates. {@link #add} and {@link #doublePoint}
 * work affinely, one {@link Fp2Element#inverse()} each. {@link #multiply} runs
 * in Jacobian coordinates ({@code x = X/Z^2}, {@code y = Y/Z^3}) with mixed
 * additions of affine points, and {@link #constantTimeMultiply} in
 * homogeneous projective coordinates ({@code x = X/Z}, {@code y = Y/Z}) with
 * complete formulas, so each needs a single inversion to return to affine
 * form at the end.
 * <p>
 * Two scalar-multiplication APIs are provided: {@link #multiply} is the
 * variable-time double-and-add — fast for public scalars (cofactor
 * clearing, subgroup checks) but unsafe for secret scalars; and
 * {@link #constantTimeMultiply} has a fixed iteration pattern, for use with
 * secret scalars (e.g. {@code sk * H(msg)} in BLS sign).
 */
public final class BLS12_381G2Point
{
    /** B coefficient: 4 * (1 + I). */
    public static final Fp2Element B = Fp2Element.of(4, 4);

    /** The point at infinity (identity element). */
    public static final BLS12_381G2Point INFINITY = new BLS12_381G2Point(null, null, true);

    private final Fp2Element x;
    private final Fp2Element y;
    private final boolean infinity;

    private BLS12_381G2Point(Fp2Element x, Fp2Element y, boolean infinity)
    {
        this.x = x;
        this.y = y;
        this.infinity = infinity;
    }

    /**
     * Constructs a G2 point from affine coordinates and verifies that
     * {@code (x, y)} satisfies the curve equation {@code y^2 = x^3 + 4*(1+I)}.
     */
    public static BLS12_381G2Point of(Fp2Element x, Fp2Element y)
    {
        Fp2Element lhs = y.square();
        Fp2Element rhs = x.square().mul(x).add(B);
        if (!lhs.equals(rhs))
        {
            throw new IllegalArgumentException("point not on BLS12-381 G2 curve E");
        }
        return new BLS12_381G2Point(x, y, false);
    }

    /**
     * Skips the curve-equation check. Used by callers that have already
     * verified the point is on the curve (e.g. immediately after iso_3
     * evaluation in hash-to-curve).
     */
    static BLS12_381G2Point ofUnchecked(Fp2Element x, Fp2Element y)
    {
        return new BLS12_381G2Point(x, y, false);
    }

    public boolean isInfinity()
    {
        return infinity;
    }

    public Fp2Element x()
    {
        return x;
    }

    public Fp2Element y()
    {
        return y;
    }

    public BLS12_381G2Point negate()
    {
        return infinity ? this : new BLS12_381G2Point(x, y.neg(), false);
    }

    public BLS12_381G2Point add(BLS12_381G2Point other)
    {
        if (infinity)
        {
            return other;
        }
        if (other.infinity)
        {
            return this;
        }
        if (x.equals(other.x))
        {
            if (y.equals(other.y))
            {
                return doublePoint();
            }
            // y == -other.y => P + (-P) = O
            return INFINITY;
        }
        // slope = (y2 - y1) / (x2 - x1)
        Fp2Element slope = other.y.sub(y).mul(other.x.sub(x).inverse());
        Fp2Element x3 = slope.square().sub(x).sub(other.x);
        Fp2Element y3 = slope.mul(x.sub(x3)).sub(y);
        return new BLS12_381G2Point(x3, y3, false);
    }

    public BLS12_381G2Point doublePoint()
    {
        if (infinity || y.isZero())
        {
            return INFINITY;
        }
        // slope = (3*x^2) / (2*y)  (curve has A = 0)
        Fp2Element xSquared = x.square();
        Fp2Element threeXSquared = xSquared.add(xSquared).add(xSquared);
        Fp2Element twoY = y.add(y);
        Fp2Element slope = threeXSquared.mul(twoY.inverse());
        Fp2Element x3 = slope.square().sub(x.add(x));
        Fp2Element y3 = slope.mul(x.sub(x3)).sub(y);
        return new BLS12_381G2Point(x3, y3, false);
    }

    /**
     * Constant-time scalar multiplication, suitable for secret scalars
     * (e.g. {@code sk * H(msg)} in BLS sign).
     * <p>
     * Points in G2 (the usual case, checked with
     * {@link BLS12_381SubgroupCheck#isInG2Subgroup}, which looks only at the
     * public point) use the GLS method, with four 64-bit digits and the
     * endomorphism &psi; (64 doublings and 64 additions). Other points use a
     * fixed-iteration "double, add, select" ladder over the low 256 bits of
     * the scalar.
     * <p>
     * Both run the same instructions whatever the scalar: the scalar is taken
     * as fixed-width limbs, reduced mod r and split into its GLS digits by
     * masked subtractions ({@link BLS12_381Scalar}); every step makes the same
     * point operations, with the complete addition and doubling formulas of
     * Renes, Costello and Batina, which have no exceptional cases for the
     * point at infinity or equal inputs on a curve of odd order, as this one
     * is; a table entry is read by a scan of every entry under a mask, and the
     * ladder keeps the sum or the double by a masked select. The field
     * arithmetic is constant time ({@link Fp}). What remains is the
     * conversion of the scalar from a {@link BigInteger}, whose own
     * representation follows its magnitude, and the JVM itself, whose cache,
     * GC and JIT behaviour pure Java cannot fully control: not a substitute
     * for a constant-time native implementation against a co-located
     * adversary with cache-line resolution.
     */
    public BLS12_381G2Point constantTimeMultiply(BigInteger scalar)
    {
        if (scalar == null)
        {
            throw new IllegalArgumentException("scalar must not be null");
        }
        if (scalar.signum() < 0)
        {
            return negate().constantTimeMultiply(scalar.negate());
        }
        if (infinity)
        {
            return INFINITY;
        }
        if (BLS12_381SubgroupCheck.isInG2Subgroup(this))
        {
            return constantTimeMultiplyInG2(scalar);
        }

        int[] k = BLS12_381Scalar.low256(scalar);
        try
        {
            return ladder(k);
        }
        finally
        {
            Arrays.fill(k, 0);
        }
    }

    /**
     * Constant-time scalar multiplication by the unsigned big-endian scalar of
     * at most 32 bytes, such as {@code BLSPrivateKeyParameters.getEncoded()}:
     * as {@link #constantTimeMultiply(BigInteger)}, but the scalar is converted
     * to fixed-width limbs directly, never held as a {@link BigInteger}.
     *
     * @throws IllegalArgumentException if the scalar is null or longer than 32 bytes.
     */
    public BLS12_381G2Point constantTimeMultiply(byte[] scalar)
    {
        int[] k = BLS12_381Scalar.fromBytes(scalar);
        try
        {
            if (infinity)
            {
                return INFINITY;
            }
            if (BLS12_381SubgroupCheck.isInG2Subgroup(this))
            {
                int[] kr = BLS12_381Scalar.modOrder(k);
                try
                {
                    return constantTimeMultiplyInG2(kr);
                }
                finally
                {
                    Arrays.fill(kr, 0);
                }
            }
            return ladder(k);
        }
        finally
        {
            Arrays.fill(k, 0);
        }
    }

    /**
     * [k] P, for k as limbs, by a fixed-iteration "double, add, select" ladder
     * over all 256 bits.
     */
    private BLS12_381G2Point ladder(int[] k)
    {
        Fp2Element[] q = { x, y, Fp2Element.ONE };
        Fp2Element[] r = PROJECTIVE_INFINITY;
        for (int i = 255; i >= 0; --i)
        {
            r = completeDouble(r);
            Fp2Element[] s = completeAdd(r, q);
            int bit = (k[i >>> 5] >>> (i & 31)) & 1;
            r = new Fp2Element[]{ Fp2Element.select(bit, s[0], r[0]), Fp2Element.select(bit, s[1], r[1]),
                Fp2Element.select(bit, s[2], r[2]) };
        }
        return fromProjective(r);
    }

    /**
     * Constant-time scalar multiplication for a point known to be in G2, by
     * the GLS method: &psi; acts on G2 as multiplication by the BLS parameter
     * x = -|x|, and r = x^4 - x^2 + 1 &lt; |x|^4, so {@code k mod r} has four
     * base-|x| digits below 2^64 and
     * {@code [k] P = [k0] P - [k1] ψ(P) + [k2] ψ²(P) - [k3] ψ³(P)}. The four
     * multiplications share 64 doublings, and each step adds one of the 16
     * subset sums of the four base points from a table, the point at infinity
     * among them, read by a masked scan of all of them: 64 doublings and 64
     * additions instead of 256 of each. The notes on
     * {@link #constantTimeMultiply} apply here too.
     * <p>
     * The result is wrong for a point outside G2; callers must know the point
     * is in G2, as hash-to-curve output is.
     */
    BLS12_381G2Point constantTimeMultiplyInG2(BigInteger scalar)
    {
        int[] k = BLS12_381Scalar.modOrder(scalar);
        try
        {
            return constantTimeMultiplyInG2(k);
        }
        finally
        {
            Arrays.fill(k, 0);
        }
    }

    /**
     * {@link #constantTimeMultiplyInG2(BigInteger)} for a scalar given as
     * limbs, already reduced mod r.
     */
    BLS12_381G2Point constantTimeMultiplyInG2(int[] k)
    {
        if (infinity)
        {
            return INFINITY;
        }

        long[] d = BLS12_381Scalar.glsDigits(k);
        try
        {
            // Base points (-1)^i psi^i(P), since |x|^i = (-1)^i x^i.
            BLS12_381G2Point[] base = new BLS12_381G2Point[4];
            base[0] = this;
            BLS12_381G2Point psi = this;
            for (int i = 1; i < 4; ++i)
            {
                psi = BLS12_381SubgroupCheck.psiG2(psi);
                base[i] = (i & 1) != 0 ? psi.negate() : psi;
            }

            // (tx, ty, tz)[b] = sum of base[i] over the bits i of b, projective; entry 0 is infinity.
            Fp2Element[] tx = new Fp2Element[16];
            Fp2Element[] ty = new Fp2Element[16];
            Fp2Element[] tz = new Fp2Element[16];
            tx[0] = PROJECTIVE_INFINITY[0];
            ty[0] = PROJECTIVE_INFINITY[1];
            tz[0] = PROJECTIVE_INFINITY[2];
            for (int b = 1; b < 16; ++b)
            {
                int low = b & -b;
                int i = low == 1 ? 0 : low == 2 ? 1 : low == 4 ? 2 : 3;
                Fp2Element[] e = completeAdd(new Fp2Element[]{ tx[b ^ low], ty[b ^ low], tz[b ^ low] },
                    new Fp2Element[]{ base[i].x, base[i].y, Fp2Element.ONE });
                tx[b] = e[0];
                ty[b] = e[1];
                tz[b] = e[2];
            }

            Fp2Element[] r = PROJECTIVE_INFINITY;
            for (int bit = 63; bit >= 0; --bit)
            {
                r = completeDouble(r);
                int idx = (int)((d[0] >>> bit) & 1) | (int)((d[1] >>> bit) & 1) << 1
                    | (int)((d[2] >>> bit) & 1) << 2 | (int)((d[3] >>> bit) & 1) << 3;
                r = completeAdd(r, new Fp2Element[]{ Fp2Element.lookup(tx, idx), Fp2Element.lookup(ty, idx),
                    Fp2Element.lookup(tz, idx) });
            }
            return fromProjective(r);
        }
        finally
        {
            Arrays.fill(d, 0L);
        }
    }

    /**
     * Variable-time double-and-add scalar multiplication. Suitable for
     * non-secret scalars (e.g. cofactor clearing); not safe for secret
     * scalar use — see {@link #constantTimeMultiply}.
     */
    public BLS12_381G2Point multiply(BigInteger scalar)
    {
        if (scalar.signum() == 0 || infinity)
        {
            return INFINITY;
        }
        if (scalar.signum() < 0)
        {
            return negate().multiply(scalar.negate());
        }
        Fp2Element[] r = JACOBIAN_INFINITY;
        for (int i = scalar.bitLength() - 1; i >= 0; --i)
        {
            r = jacobianDouble(r);
            if (scalar.testBit(i))
            {
                r = jacobianAddAffine(r, x, y);
            }
        }
        return fromJacobian(r);
    }

    /** |x| for the BLS parameter x = -0xd201000000010000; &psi; acts on G2 as [x]. */
    private static final BigInteger ABS_X = new BigInteger("d201000000010000", 16);

    /** The point at infinity in Jacobian coordinates (any point with Z = 0). */
    private static final Fp2Element[] JACOBIAN_INFINITY = { Fp2Element.ONE, Fp2Element.ONE, Fp2Element.ZERO };

    /**
     * Jacobian doubling for a = 0 (dbl-2009-l, Explicit-Formulas Database):
     * 2M + 5S. Z = 0 (infinity) and Y = 0 (order 2) both give Z3 = 0, so
     * neither needs a branch.
     */
    private static Fp2Element[] jacobianDouble(Fp2Element[] p)
    {
        Fp2Element x1 = p[0], y1 = p[1], z1 = p[2];
        Fp2Element a = x1.square();
        Fp2Element b = y1.square();
        Fp2Element c = b.square();
        Fp2Element t = x1.add(b).square().sub(a).sub(c);
        Fp2Element d = t.add(t);
        Fp2Element e = a.add(a).add(a);
        Fp2Element f = e.square();
        Fp2Element x3 = f.sub(d.add(d));
        Fp2Element c8 = c.add(c);
        c8 = c8.add(c8);
        c8 = c8.add(c8);
        Fp2Element y3 = e.mul(d.sub(x3)).sub(c8);
        Fp2Element yz = y1.mul(z1);
        Fp2Element z3 = yz.add(yz);
        return new Fp2Element[]{ x3, y3, z3 };
    }

    /**
     * Mixed addition of a Jacobian point and an affine point (madd-2007-bl,
     * Explicit-Formulas Database): 7M + 4S. Handles {@code p} at infinity
     * and the doubling and inverse cases, which the formula does not.
     */
    private static Fp2Element[] jacobianAddAffine(Fp2Element[] p, Fp2Element x2, Fp2Element y2)
    {
        Fp2Element x1 = p[0], y1 = p[1], z1 = p[2];
        if (z1.isZero())
        {
            return new Fp2Element[]{ x2, y2, Fp2Element.ONE };
        }
        Fp2Element z1z1 = z1.square();
        Fp2Element u2 = x2.mul(z1z1);
        Fp2Element s2 = y2.mul(z1).mul(z1z1);
        Fp2Element h = u2.sub(x1);
        Fp2Element sy = s2.sub(y1);
        if (h.isZero())
        {
            // Same x: P + P is a doubling, P + (-P) is infinity.
            return sy.isZero() ? jacobianDouble(p) : JACOBIAN_INFINITY;
        }
        Fp2Element hh = h.square();
        Fp2Element i = hh.add(hh);
        i = i.add(i);
        Fp2Element j = h.mul(i);
        Fp2Element r = sy.add(sy);
        Fp2Element v = x1.mul(i);
        Fp2Element x3 = r.square().sub(j).sub(v.add(v));
        Fp2Element y1j = y1.mul(j);
        Fp2Element y3 = r.mul(v.sub(x3)).sub(y1j.add(y1j));
        Fp2Element z3 = z1.add(h).square().sub(z1z1).sub(hh);
        return new Fp2Element[]{ x3, y3, z3 };
    }

    /** Converts Jacobian {@code (X, Y, Z)} to the affine point {@code (X/Z^2, Y/Z^3)}. */
    private static BLS12_381G2Point fromJacobian(Fp2Element[] p)
    {
        if (p[2].isZero())
        {
            return INFINITY;
        }
        Fp2Element zInv = p[2].inverse();
        Fp2Element zInv2 = zInv.square();
        return new BLS12_381G2Point(p[0].mul(zInv2), p[1].mul(zInv2).mul(zInv), false);
    }

    /** The point at infinity in homogeneous projective coordinates. */
    private static final Fp2Element[] PROJECTIVE_INFINITY = { Fp2Element.ZERO, Fp2Element.ONE, Fp2Element.ZERO };

    /** a * 3b' for b' = 4(1 + I): 12 a (1 + I). */
    private static Fp2Element mulB3(Fp2Element a)
    {
        Fp2Element t = a.mulByNonResidue();
        Fp2Element t4 = t.add(t);
        t4 = t4.add(t4);
        Fp2Element t8 = t4.add(t4);
        return t8.add(t4);
    }

    /**
     * Complete addition in homogeneous projective coordinates for a = 0:
     * Algorithm 7 of Renes, Costello and Batina, "Complete addition formulas
     * for prime order elliptic curves" (EUROCRYPT 2016), 12M. Correct for every
     * pair of inputs, the point at infinity and equal points included, on a
     * curve with no point of order 2, which E'(Fp^2) has not (its order is
     * odd).
     */
    private static Fp2Element[] completeAdd(Fp2Element[] p, Fp2Element[] q)
    {
        Fp2Element x1 = p[0], y1 = p[1], z1 = p[2];
        Fp2Element x2 = q[0], y2 = q[1], z2 = q[2];
        Fp2Element t0 = x1.mul(x2);
        Fp2Element t1 = y1.mul(y2);
        Fp2Element t2 = z1.mul(z2);
        Fp2Element t3 = x1.add(y1).mul(x2.add(y2)).sub(t0.add(t1));
        Fp2Element t4 = y1.add(z1).mul(y2.add(z2)).sub(t1.add(t2));
        Fp2Element y3 = x1.add(z1).mul(x2.add(z2)).sub(t0.add(t2));
        t0 = t0.add(t0).add(t0);
        t2 = mulB3(t2);
        Fp2Element z3 = t1.add(t2);
        t1 = t1.sub(t2);
        y3 = mulB3(y3);
        Fp2Element x3 = t3.mul(t1).sub(t4.mul(y3));
        y3 = t1.mul(z3).add(y3.mul(t0));
        z3 = z3.mul(t4).add(t0.mul(t3));
        return new Fp2Element[]{ x3, y3, z3 };
    }

    /**
     * Doubling in homogeneous projective coordinates for a = 0: Algorithm 9 of
     * Renes, Costello and Batina, 6M + 2S; the point at infinity doubles to
     * itself.
     */
    private static Fp2Element[] completeDouble(Fp2Element[] p)
    {
        Fp2Element x = p[0], y = p[1], z = p[2];
        Fp2Element t0 = y.square();
        Fp2Element z3 = t0.add(t0);
        z3 = z3.add(z3);
        z3 = z3.add(z3);
        Fp2Element t1 = y.mul(z);
        Fp2Element t2 = mulB3(z.square());
        Fp2Element x3 = t2.mul(z3);
        Fp2Element y3 = t0.add(t2);
        z3 = t1.mul(z3);
        t2 = t2.add(t2).add(t2);
        t0 = t0.sub(t2);
        y3 = x3.add(t0.mul(y3));
        x3 = t0.mul(x.mul(y));
        x3 = x3.add(x3);
        return new Fp2Element[]{ x3, y3, z3 };
    }

    /** Converts projective {@code (X : Y : Z)} to the affine point {@code (X/Z, Y/Z)}. */
    private static BLS12_381G2Point fromProjective(Fp2Element[] p)
    {
        if (p[2].isZero())
        {
            return INFINITY;
        }
        Fp2Element zInv = p[2].inverse();
        return new BLS12_381G2Point(p[0].mul(zInv), p[1].mul(zInv), false);
    }

    public boolean equals(Object other)
    {
        if (!(other instanceof BLS12_381G2Point))
        {
            return false;
        }
        BLS12_381G2Point o = (BLS12_381G2Point)other;
        if (infinity || o.infinity)
        {
            return infinity == o.infinity;
        }
        return x.equals(o.x) && y.equals(o.y);
    }

    public int hashCode()
    {
        if (infinity)
        {
            return 0;
        }
        return x.hashCode() * 31 + y.hashCode();
    }

    public String toString()
    {
        if (infinity)
        {
            return "G2(infinity)";
        }
        return "G2(" + x + ", " + y + ")";
    }
}
