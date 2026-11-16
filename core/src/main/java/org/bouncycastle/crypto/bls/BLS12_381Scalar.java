package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Fixed-width handling of secret scalars for the BLS12-381 constant-time
 * multiplications: a scalar as eight 32-bit limbs, least significant first,
 * its reduction mod r, and its four GLS digits in base |x|, each by the same
 * instructions whatever its value.
 * <p>
 * A scalar given as a {@link BigInteger} brings the variable-time
 * representation of that class with it; one given as bytes, as a private key
 * is held by {@code BLSPrivateKeyParameters}, is converted to limbs by the same
 * instructions whatever its value. Only the choice of path for a
 * {@link BigInteger} of more than 256 bits, which no private key is, looks at
 * the value beyond its conversion.
 */
final class BLS12_381Scalar
{
    static final int SIZE = 8;

    private static final long M = 0xFFFFFFFFL;

    /** r, the order of G1 and G2. */
    private static final int[] R = Nat.fromBigInteger(256, BLS12_381G1.ORDER);

    private static final BigInteger MASK_256 = BigIntegers.ONE.shiftLeft(256).subtract(BigIntegers.ONE);

    /** |x| for the BLS parameter x = -0xd201000000010000. */
    static final long ABS_X = 0xd201000000010000L;

    /**
     * The low 256 bits of the non-negative k, as limbs.
     */
    static int[] low256(BigInteger k)
    {
        if (k.bitLength() > 256)
        {
            k = k.and(MASK_256);
        }
        return Nat.fromBigInteger(256, k);
    }

    /**
     * The unsigned big-endian value of b, at most 32 bytes, as limbs.
     */
    static int[] fromBytes(byte[] b)
    {
        if (b == null || b.length > 32)
        {
            throw new IllegalArgumentException("scalar must be at most 32 bytes");
        }
        int[] z = new int[SIZE];
        for (int i = 0; i < b.length; ++i)
        {
            int j = b.length - 1 - i;
            z[j >>> 2] |= (b[i] & 0xFF) << ((j & 3) << 3);
        }
        return z;
    }

    /**
     * k, as 32 big-endian bytes.
     */
    static byte[] toBytes(int[] k)
    {
        byte[] b = new byte[32];
        for (int i = 0; i < 32; ++i)
        {
            int j = 31 - i;
            b[i] = (byte)(k[j >>> 2] >>> ((j & 3) << 3));
        }
        return b;
    }

    /**
     * Whether k is a valid secret key, in [1, r - 1], the limbs examined
     * without an early exit.
     */
    static boolean isValidSecret(int[] k)
    {
        int d = 0;
        for (int i = 0; i < SIZE; ++i)
        {
            d |= k[i];
        }
        // lessThan gives -1 if k < r and 0 if not; d is nonzero if k is
        return (Nat.lessThan(SIZE, k, R) & ((d | -d) >> 31)) != 0;
    }

    /**
     * The secret key encoded as sk, the 32 big-endian bytes of
     * draft-irtf-cfrg-bls-signature, as limbs.
     *
     * @throws IllegalArgumentException if sk is not 32 bytes or not in [1, r - 1].
     */
    static int[] secretFromBytes(byte[] sk)
    {
        if (sk == null || sk.length != 32)
        {
            throw new IllegalArgumentException("invalid secret key");
        }
        int[] k = fromBytes(sk);
        if (!isValidSecret(k))
        {
            Arrays.fill(k, 0);
            throw new IllegalArgumentException("invalid secret key");
        }
        return k;
    }

    /**
     * The unsigned big-endian value of buf[off..off + len) mod r, as limbs,
     * bit by bit from the top: the remainder, below r &lt; 2^255, is doubled
     * and takes the next bit, staying below 2r &lt; 2^256, and r is subtracted
     * from it under a mask.
     */
    static int[] reduce(byte[] buf, int off, int len)
    {
        int[] z = new int[SIZE];
        int[] t = new int[SIZE];
        for (int i = 0; i < len << 3; ++i)
        {
            int bit = (buf[off + (i >>> 3)] >>> (7 - (i & 7))) & 1;
            Nat.shiftUpBit(SIZE, z, bit << 31);
            int borrow = Nat.sub(SIZE, z, R, t);
            Nat.cmov(SIZE, borrow + 1, t, 0, z, 0);
        }
        Arrays.fill(t, 0);
        return z;
    }

    /**
     * k mod r for the non-negative k, as limbs.
     */
    static int[] modOrder(BigInteger k)
    {
        if (k.bitLength() > 256)
        {
            k = k.mod(BLS12_381G1.ORDER);
        }
        return modOrder(Nat.fromBigInteger(256, k));
    }

    /**
     * k mod r for k given as limbs, below 2^256, which is below 3r: two
     * subtractions of r, each kept or discarded under a mask. k is not changed.
     */
    static int[] modOrder(int[] k)
    {
        int[] z = Arrays.clone(k);
        int[] t = new int[SIZE];
        for (int i = 0; i < 2; ++i)
        {
            // the borrow is 0 when z >= r, -1 when not: z - r is kept in the first case
            int borrow = Nat.sub(SIZE, z, R, t);
            Nat.cmov(SIZE, borrow + 1, t, 0, z, 0);
        }
        Arrays.fill(t, 0);
        return z;
    }

    /**
     * The four base-|x| digits of k, given as limbs below r, least significant
     * first, each below |x|; as r &lt; |x|^4 the quotient left after three
     * divisions is the fourth.
     * <p>
     * Each division by |x| is restoring binary long division over all 256 bits:
     * the remainder, below |x| &lt; 2^64, takes the next bit of the dividend,
     * and |x| is subtracted from it, the difference kept under a mask taken
     * from the borrow of the subtraction and the bit shifted out of the top of
     * the remainder, which together say whether the 65-bit value was at least
     * |x|.
     */
    static long[] glsDigits(int[] k)
    {
        long[] d = new long[4];
        int[] q = Arrays.clone(k);
        int[] n = new int[SIZE];
        for (int j = 0; j < 3; ++j)
        {
            long rem = 0;
            for (int i = 255; i >= 0; --i)
            {
                long hi = rem >>> 63;
                rem = (rem << 1) | ((q[i >>> 5] >>> (i & 31)) & 1);
                long diff = rem - ABS_X;
                long borrow = ((~rem & ABS_X) | (~(rem ^ ABS_X) & diff)) >>> 63;
                long take = hi | (borrow ^ 1);
                long mask = -take;
                rem = (diff & mask) | (rem & ~mask);
                n[i >>> 5] |= (int)take << (i & 31);
            }
            d[j] = rem;
            int[] t = q;
            q = n;
            n = t;
            Arrays.fill(n, 0);
        }
        d[3] = (q[0] & M) | ((long)q[1] << 32);
        Arrays.fill(q, 0);
        return d;
    }

    private BLS12_381Scalar()
    {
    }
}
