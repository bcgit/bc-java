package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Affine point of the group G2 for SM9: the sextic twist E'(F_p2): y^2 = x^3 + 5u
 * (GM/T 0044.5-2016). Immutable. G1 by contrast is an ordinary prime-field curve
 * handled by {@link org.bouncycastle.math.ec.ECCurve.Fp}.
 */
public class SM9G2Point
{
    static final SM9G2Point INFINITY = new SM9G2Point();

    final Fp2 x;
    final Fp2 y;
    final boolean infinity;

    private SM9G2Point()
    {
        this.x = null;
        this.y = null;
        this.infinity = true;
    }

    SM9G2Point(Fp2 x, Fp2 y)
    {
        this.x = x;
        this.y = y;
        this.infinity = false;
    }

    public boolean isInfinity()
    {
        return infinity;
    }

//    SM9G2Point negate()
//    {
//        return infinity ? this : new SM9G2Point(x, y.negate());
//    }

    SM9G2Point twice()
    {
        if (infinity || y.isZero())
        {
            return INFINITY;
        }
        Fp2 x2 = x.square();
        Fp2 num = x2.add(x2).add(x2);   // 3x^2  (a = 0 for this curve)
        Fp2 den = y.add(y);             // 2y
        Fp2 lam = num.multiply(den.invert());
        Fp2 x3 = lam.square().subtract(x).subtract(x);
        Fp2 y3 = lam.multiply(x.subtract(x3)).subtract(y);
        return new SM9G2Point(x3, y3);
    }

    public SM9G2Point add(SM9G2Point o)
    {
        if (infinity)
        {
            return o;
        }
        if (o.infinity)
        {
            return this;
        }
        if (x.equals(o.x))
        {
            if (y.add(o.y).isZero())
            {
                return INFINITY;
            }
            return twice();
        }
        Fp2 lam = o.y.subtract(y).multiply(o.x.subtract(x).invert());
        Fp2 x3 = lam.square().subtract(x).subtract(o.x);
        Fp2 y3 = lam.multiply(x.subtract(x3)).subtract(y);
        return new SM9G2Point(x3, y3);
    }

    /**
     * Scalar multiplication by a Montgomery ladder, maintaining the invariant
     * r1 = r0 + this and returning [k]this. The loop runs a fixed,
     * scalar-independent number of iterations (the group order bit length) doing
     * exactly one point addition and one doubling per bit, so it removes the
     * Hamming-weight and bit-length leaks of the plain double-and-add it replaces.
     * <p>
     * NOTE: this is a hardening, not a full constant-time guarantee. The per-bit
     * if/else selects which running point is updated (a data-dependent branch), the
     * INFINITY fast paths in {@link #add}/{@link #twice} make the leading-zero prefix
     * of the scalar cheaper (leaking its most-significant-bit position), and the
     * underlying F_p2 arithmetic is BigInteger-based and not itself constant time.
     * It is used only for the two secret scalars in offline KGC key derivation
     * ([ks]P2 and [t2]P2); a fully constant-time G2 would need a uniform,
     * sentinel-free point representation over a fixed-limb F_p2.
     */
    public SM9G2Point multiply(BigInteger k)
    {
        if (infinity || k.signum() == 0)
        {
            return INFINITY;
        }

        SM9G2Point r0 = INFINITY;
        SM9G2Point r1 = this;
        for (int i = SM9Curve.N.bitLength() - 1; i >= 0; --i)
        {
            if (k.testBit(i))
            {
                r0 = r0.add(r1);   // bit 1: (r0, r1) <- (r0 + r1, 2 r1)
                r1 = r1.twice();
            }
            else
            {
                r1 = r0.add(r1);   // bit 0: (r0, r1) <- (2 r0, r0 + r1)
                r0 = r0.twice();
            }
        }
        return r0;
    }

    /**
     * Uncompressed encoding 0x04 || x || y, each F_p2 coordinate written high
     * dimension first (u-coefficient then constant), 32 bytes per F_p component;
     * 129 bytes total.
     */
    public byte[] getEncoded()
    {
        byte[] out = new byte[129];
        out[0] = 0x04;
        System.arraycopy(fp2Bytes(x), 0, out, 1, 64);
        System.arraycopy(fp2Bytes(y), 0, out, 65, 64);
        return out;
    }

    // twist b' = 5u for E'(F_p2): y^2 = x^3 + 5u (GM/T 0044.5), used to validate imported points.
    private static final Fp2 B_TWIST = new Fp2(BigInteger.ZERO, BigInteger.valueOf(5));

    public static SM9G2Point decode(byte[] enc)
    {
        if (enc.length != 129 || enc[0] != 0x04)
        {
            throw new IllegalArgumentException("invalid SM9 G2 point encoding");
        }
        SM9G2Point p = new SM9G2Point(fp2FromBytes(enc, 1), fp2FromBytes(enc, 65));
        if (!p.isOnCurve(B_TWIST))
        {
            throw new IllegalArgumentException("SM9 G2 point not on the twist curve");
        }
        return p;
    }

    private static byte[] fp2Bytes(Fp2 e)
    {
        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(32, e.b),   // high dimension (u-coefficient)
            BigIntegers.asUnsignedByteArray(32, e.a));  // low dimension (constant)
    }

    private static Fp2 fp2FromBytes(byte[] enc, int off)
    {
        BigInteger hi = new BigInteger(1, Arrays.copyOfRange(enc, off, off + 32));
        BigInteger lo = new BigInteger(1, Arrays.copyOfRange(enc, off + 32, off + 64));
        return new Fp2(lo, hi);
    }

    boolean isOnCurve(Fp2 bTwist)
    {
        if (infinity)
        {
            return true;
        }
        return y.square().equals(x.square().multiply(x).add(bTwist));
    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof SM9G2Point))
        {
            return false;
        }
        SM9G2Point o = (SM9G2Point)other;
        if (infinity || o.infinity)
        {
            return infinity == o.infinity;
        }
        return x.equals(o.x) && y.equals(o.y);
    }

    public int hashCode()
    {
        return infinity ? 0 : (x.hashCode() ^ (y.hashCode() * 31));
    }
}
