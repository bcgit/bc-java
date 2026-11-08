package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

/**
 * Affine point on the BLS12-381 G2 curve {@code E: y^2 = x^3 + 4*(1+I)} over
 * Fp^2.
 * <p>
 * Points are held in affine coordinates. {@link #add} and {@link #doublePoint}
 * work affinely, one {@link Fp2Element#inverse()} each; the two scalar
 * multiplications run in Jacobian coordinates ({@code x = X/Z^2},
 * {@code y = Y/Z^3}) with mixed additions of affine points, so they need a
 * single inversion to return to affine form at the end (plus one for the
 * GLS table of {@link #constantTimeMultiply} on G2).
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
        Fp2Element threeXSquared = x.square().mulFp(BigInteger.valueOf(3));
        Fp2Element twoY = y.mulFp(BigInteger.valueOf(2));
        Fp2Element slope = threeXSquared.mul(twoY.inverse());
        Fp2Element x3 = slope.square().sub(x.mulFp(BigInteger.valueOf(2)));
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
     * fixed-iteration
     * "double, conditionally add" ladder over 256 bits. In both, the
     * conditional addition is always computed and then chosen by an
     * array-indexed select rather than an {@code if}, so every iteration
     * performs the same point operations whatever the scalar bits.
     * <p>
     * <b>Caveats.</b> "Constant-time" here means the
     * scalar-bit-pattern-independent at the scalar-mult loop level.
     * The underlying Jacobian point ops still have data-dependent branches
     * for the infinity / equal-x cases of the mixed addition (the accumulator
     * is at infinity until the scalar's first set bit; the equal-x cases are
     * negligibly probable for random secret scalars on a prime-order
     * subgroup), the {@link BigInteger} field arithmetic is not constant
     * time, and the JVM
     * itself may introduce cache / GC / JIT timing variance that pure
     * Java cannot fully eliminate. Sufficient against a remote network
     * timing attacker on a typical workload; not a substitute for a
     * constant-time native implementation against a co-located
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

        // Fixed-width scalar handling: read 256 bits regardless of the
        // actual bit length of scalar, so the iteration count carries no
        // information about the secret.
        final int FIXED_BITS = 256;
        Fp2Element[] r = JACOBIAN_INFINITY;
        Fp2Element[][] options = new Fp2Element[2][];
        for (int i = FIXED_BITS - 1; i >= 0; --i)
        {
            r = jacobianDouble(r);
            Fp2Element[] candidate = jacobianAddAffine(r, x, y);
            options[0] = r;
            options[1] = candidate;
            int bit = scalar.testBit(i) ? 1 : 0;
            r = options[bit];
        }
        return fromJacobian(r);
    }

    /**
     * Constant-time scalar multiplication for a point known to be in G2, by
     * the GLS method: &psi; acts on G2 as multiplication by the BLS parameter
     * x = -|x|, and r = x^4 - x^2 + 1 &lt; |x|^4, so {@code k mod r} has four
     * base-|x| digits below 2^64 and
     * {@code [k] P = [k0] P - [k1] ψ(P) + [k2] ψ²(P) - [k3] ψ³(P)}. The four
     * multiplications share 64 doublings, and each step adds one of the 15
     * non-empty subset sums of the four base points from a table (always
     * computed, an addition of a dummy entry when the digit bits are all
     * zero, and chosen by an array-indexed select, as in
     * {@link #constantTimeMultiply}): 64 doublings and 64 mixed additions
     * instead of 256 of each. The caveats there apply here too.
     * <p>
     * The result is wrong for a point outside G2; callers must know the point
     * is in G2, as hash-to-curve output is.
     */
    BLS12_381G2Point constantTimeMultiplyInG2(BigInteger scalar)
    {
        if (infinity)
        {
            return INFINITY;
        }

        long[] d = new long[4];
        BigInteger k = scalar.mod(BLS12_381G2.ORDER);
        for (int i = 0; i < 4; ++i)
        {
            BigInteger[] qr = k.divideAndRemainder(ABS_X);
            d[i] = qr[1].longValue();
            k = qr[0];
        }

        // Base points (-1)^i psi^i(P), since |x|^i = (-1)^i x^i.
        BLS12_381G2Point[] base = new BLS12_381G2Point[4];
        base[0] = this;
        BLS12_381G2Point psi = this;
        for (int i = 1; i < 4; ++i)
        {
            psi = BLS12_381SubgroupCheck.psiG2(psi);
            base[i] = (i & 1) != 0 ? psi.negate() : psi;
        }

        // table[b] = sum of base[i] over the bits i of b, in Jacobian form, then
        // all made affine with one inversion (Montgomery's trick).
        Fp2Element[][] table = new Fp2Element[16][];
        for (int b = 1; b < 16; ++b)
        {
            int low = b & -b;
            int i = low == 1 ? 0 : low == 2 ? 1 : low == 4 ? 2 : 3;
            table[b] = b == low
                ? new Fp2Element[]{ base[i].x, base[i].y, Fp2Element.ONE }
                : jacobianAddAffine(table[b ^ low], base[i].x, base[i].y);
        }
        Fp2Element[] tx = new Fp2Element[16];
        Fp2Element[] ty = new Fp2Element[16];
        toAffine(table, tx, ty);

        Fp2Element[] r = JACOBIAN_INFINITY;
        Fp2Element[][] options = new Fp2Element[2][];
        for (int bit = 63; bit >= 0; --bit)
        {
            r = jacobianDouble(r);
            int idx = (int)((d[0] >>> bit) & 1) | (int)((d[1] >>> bit) & 1) << 1
                | (int)((d[2] >>> bit) & 1) << 2 | (int)((d[3] >>> bit) & 1) << 3;
            // Entry 15 stands in for the empty sum, whose sum is then discarded.
            int entry = idx | ((idx - 1) >>> 31) * 15;
            options[0] = r;
            options[1] = jacobianAddAffine(r, tx[entry], ty[entry]);
            r = options[(idx | -idx) >>> 31];
        }
        return fromJacobian(r);
    }

    /**
     * Converts {@code table[1..15]} from Jacobian to affine form with one
     * inversion: the inverse of the product of all Z, then each Z's inverse
     * from it and the prefix products (Montgomery's trick).
     */
    private static void toAffine(Fp2Element[][] table, Fp2Element[] tx, Fp2Element[] ty)
    {
        int n = table.length;
        Fp2Element[] prefix = new Fp2Element[n];
        Fp2Element acc = Fp2Element.ONE;
        for (int b = 1; b < n; ++b)
        {
            if (table[b][2].isZero())
            {
                throw new IllegalStateException("point not in G2");
            }
            prefix[b] = acc;
            acc = acc.mul(table[b][2]);
        }
        Fp2Element inv = acc.inverse();
        for (int b = n - 1; b >= 1; --b)
        {
            Fp2Element zInv = inv.mul(prefix[b]);
            inv = inv.mul(table[b][2]);
            Fp2Element zInv2 = zInv.square();
            tx[b] = table[b][0].mul(zInv2);
            ty[b] = table[b][1].mul(zInv2).mul(zInv);
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
