package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

/**
 * Affine point on the BLS12-381 G2 curve {@code E: y^2 = x^3 + 4*(1+I)} over
 * Fp^2.
 * <p>
 * Affine coordinates with each operation normalising via
 * {@link Fp2Element#inverse()}.
 * <p>
 * Two scalar-multiplication APIs are provided: {@link #multiply} is the
 * variable-time double-and-add — fast for public scalars (cofactor
 * clearing, subgroup checks) but unsafe for secret scalars; and
 * {@link #constantTimeMultiply} is a fixed-iteration ladder for use with
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
     * Uses a fixed-iteration "double, conditionally add" ladder over 256
     * bits, with the conditional-add implemented as an array-indexed
     * select rather than an {@code if}. Both branches of every iteration
     * compute the same set of point operations regardless of the
     * scalar-bit value, so the per-bit timing does not depend on
     * the scalar.
     * <p>
     * <b>Caveats.</b> "Constant-time" here means the
     * scalar-bit-pattern-independent at the scalar-mult loop level.
     * The underlying affine point ops still have data-dependent branches
     * for infinity / equal-x cases (which are negligibly probable for
     * random secret scalars on a prime-order subgroup), and the JVM
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

        // Fixed-width scalar handling: read 256 bits regardless of the
        // actual bit length of scalar, so the iteration count carries no
        // information about the secret.
        final int FIXED_BITS = 256;
        BLS12_381G2Point r = INFINITY;
        BLS12_381G2Point[] options = new BLS12_381G2Point[2];
        for (int i = FIXED_BITS - 1; i >= 0; --i)
        {
            r = r.doublePoint();
            BLS12_381G2Point candidate = r.add(this);
            options[0] = r;
            options[1] = candidate;
            int bit = scalar.testBit(i) ? 1 : 0;
            r = options[bit];
        }
        return r;
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
        BLS12_381G2Point result = INFINITY;
        BLS12_381G2Point addend = this;
        for (int i = 0; i < scalar.bitLength(); ++i)
        {
            if (scalar.testBit(i))
            {
                result = result.add(addend);
            }
            addend = addend.doublePoint();
        }
        return result;
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
