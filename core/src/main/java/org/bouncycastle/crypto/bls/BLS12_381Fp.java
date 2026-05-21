package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Nat;

/**
 * Custom-limb arithmetic in {@code Fp} for the BLS12-381 base field, where
 * {@code p} is the 381-bit prime
 * {@code 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab}.
 * <p>
 * Storage is twelve unsigned 32-bit limbs in little-endian order
 * ({@code limbs[0]} = lowest 32 bits) using Montgomery form
 * {@code x_mont = x * R mod p} with {@code R = 2^384}. Multiplication is the
 * interleaved schoolbook + Montgomery reduction (12-limb generalisation of
 * BC's existing {@code Mont256.multAdd}); inversion uses Fermat's little
 * theorem ({@code a^(p-2) mod p}) since the modulus is prime.
 * <p>
 * The class is immutable. Conversion to/from {@link BigInteger} happens at
 * the field boundary (initialisation, debugging, serialization); the inner
 * arithmetic loops never leave limb form.
 */
public final class BLS12_381Fp
{
    /**
     * BLS12-381 base field characteristic p, in twelve 32-bit limbs (little-endian).
     * Derived from {@link BLS12_381G1#Q} at class load time.
     */
    static final int[] P;

    /** -p^(-1) mod 2^32, the Montgomery reduction constant. */
    private static final int P_INV32;

    /** R^2 mod p (where R = 2^384), used to convert into Montgomery form. */
    private static final int[] R_SQ;

    /** R mod p (= 1 in Montgomery form). */
    private static final int[] R_MOD_P;

    private static final long M = 0xffffffffL;

    public static final BLS12_381Fp ZERO;

    /** The Fp identity element {@code 1} in Montgomery form. */
    public static final BLS12_381Fp ONE;

    static
    {
        BigInteger p = BLS12_381G1.Q;
        P = bigIntToLimbs(p);

        // P_INV32 = -p^(-1) mod 2^32 via Newton iteration on the low limb.
        int pLow = P[0];
        int z = pLow;             // z * pLow == 1 mod 2^3
        z *= 2 - pLow * z;        // mod 2^6
        z *= 2 - pLow * z;        // mod 2^12
        z *= 2 - pLow * z;        // mod 2^24
        z *= 2 - pLow * z;        // mod 2^48 (sufficient for 2^32)
        P_INV32 = -z;

        BigInteger r = BigInteger.ONE.shiftLeft(384);
        R_MOD_P = bigIntToLimbs(r.mod(p));
        R_SQ = bigIntToLimbs(r.multiply(r).mod(p));

        ZERO = new BLS12_381Fp(new int[12]);
        ONE = new BLS12_381Fp(R_MOD_P.clone());
    }

    private final int[] limbs;

    private BLS12_381Fp(int[] limbs)
    {
        this.limbs = limbs;
    }

    /**
     * Create an Fp element from an arbitrary BigInteger, reducing mod p and
     * converting into Montgomery form.
     */
    public static BLS12_381Fp fromBigInteger(BigInteger v)
    {
        BigInteger reduced = v.mod(BLS12_381G1.Q);
        int[] ordinary = bigIntToLimbs(reduced);
        int[] mont = new int[12];
        montMul(ordinary, R_SQ, mont);
        return new BLS12_381Fp(mont);
    }

    /**
     * Convert back to BigInteger (in [0, p)), undoing the Montgomery factor.
     */
    public BigInteger toBigInteger()
    {
        int[] one = new int[12];
        one[0] = 1;
        int[] ordinary = new int[12];
        montMul(limbs, one, ordinary);
        return limbsToBigInt(ordinary);
    }

    public boolean isZero()
    {
        for (int i = 0; i < 12; ++i)
        {
            if (limbs[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    public BLS12_381Fp add(BLS12_381Fp other)
    {
        int[] z = new int[12];
        int c = Nat.add(12, limbs, other.limbs, z);
        if (c != 0 || Nat.gte(12, z, P))
        {
            Nat.sub(12, z, P, z);
        }
        return new BLS12_381Fp(z);
    }

    public BLS12_381Fp sub(BLS12_381Fp other)
    {
        int[] z = new int[12];
        int c = Nat.sub(12, limbs, other.limbs, z);
        if (c != 0)
        {
            Nat.add(12, z, P, z);
        }
        return new BLS12_381Fp(z);
    }

    public BLS12_381Fp neg()
    {
        if (isZero())
        {
            return this;
        }
        int[] z = new int[12];
        Nat.sub(12, P, limbs, z);
        return new BLS12_381Fp(z);
    }

    public BLS12_381Fp mul(BLS12_381Fp other)
    {
        int[] z = new int[12];
        montMul(limbs, other.limbs, z);
        return new BLS12_381Fp(z);
    }

    public BLS12_381Fp square()
    {
        int[] z = new int[12];
        montMul(limbs, limbs, z);
        return new BLS12_381Fp(z);
    }

    public BLS12_381Fp shiftLeftOne()
    {
        // 2x in Mont form is just 2 * limbs (then reduce). Equivalently x.add(x).
        return add(this);
    }

    public BLS12_381Fp inverse()
    {
        // Fermat: a^(p-2) mod p.
        BigInteger pMinus2 = BLS12_381G1.Q.subtract(BigInteger.valueOf(2));
        return modPow(pMinus2);
    }

    public BLS12_381Fp modPow(BigInteger exponent)
    {
        BLS12_381Fp result = ONE;
        BLS12_381Fp base = this;
        for (int i = 0; i < exponent.bitLength(); ++i)
        {
            if (exponent.testBit(i))
            {
                result = result.mul(base);
            }
            base = base.square();
        }
        return result;
    }

    public boolean equals(Object other)
    {
        if (!(other instanceof BLS12_381Fp))
        {
            return false;
        }
        BLS12_381Fp o = (BLS12_381Fp)other;
        for (int i = 0; i < 12; ++i)
        {
            if (limbs[i] != o.limbs[i])
            {
                return false;
            }
        }
        return true;
    }

    public int hashCode()
    {
        int h = 0;
        for (int i = 0; i < 12; ++i)
        {
            h = h * 31 + limbs[i];
        }
        return h;
    }

    public String toString()
    {
        return toBigInteger().toString(16);
    }

    /**
     * Interleaved Montgomery multiplication: {@code z = x * y * R^(-1) mod p}.
     * Twelve-limb specialisation of BC's {@code Mont256.multAdd} pattern.
     * On entry {@code z} is treated as zero; on exit {@code z} holds the product.
     */
    private static void montMul(int[] x, int[] y, int[] z)
    {
        java.util.Arrays.fill(z, 0);
        int z_top = 0;
        long y_0 = y[0] & M;
        for (int i = 0; i < 12; ++i)
        {
            long z_0 = z[0] & M;
            long x_i = x[i] & M;

            long prod1 = x_i * y_0;
            long carry = (prod1 & M) + z_0;

            long t = ((int)carry * (long)P_INV32) & M;

            long prod2 = t * (P[0] & M);
            carry += (prod2 & M);
            // assert (int)carry == 0;
            carry = (carry >>> 32) + (prod1 >>> 32) + (prod2 >>> 32);

            for (int j = 1; j < 12; ++j)
            {
                prod1 = x_i * (y[j] & M);
                prod2 = t * (P[j] & M);

                carry += (prod1 & M) + (prod2 & M) + (z[j] & M);
                z[j - 1] = (int)carry;
                carry = (carry >>> 32) + (prod1 >>> 32) + (prod2 >>> 32);
            }

            carry += (z_top & M);
            z[11] = (int)carry;
            z_top = (int)(carry >>> 32);
        }
        if (z_top != 0 || Nat.gte(12, z, P))
        {
            Nat.sub(12, z, P, z);
        }
    }

    private static int[] bigIntToLimbs(BigInteger v)
    {
        // v is in [0, p), i.e. fits in 12 32-bit words.
        int[] out = new int[12];
        BigInteger mask = BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE);
        BigInteger work = v;
        for (int i = 0; i < 12; ++i)
        {
            out[i] = work.and(mask).intValue();
            work = work.shiftRight(32);
        }
        return out;
    }

    private static BigInteger limbsToBigInt(int[] limbs)
    {
        BigInteger r = BigInteger.ZERO;
        for (int i = 11; i >= 0; --i)
        {
            r = r.shiftLeft(32).add(BigInteger.valueOf(limbs[i] & M));
        }
        return r;
    }
}
