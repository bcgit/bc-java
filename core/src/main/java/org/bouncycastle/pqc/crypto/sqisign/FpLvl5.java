package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * GF(p) arithmetic for SQIsign level 5, where p = 27 * 2^500 - 1 (505-bit
 * prime). Java-side mirror of {@code src/gf/ref/lvl5/ (analogous fp implementation)} from the
 * SQIsign reference C implementation, plus {@code src/gf/ref/lvlx/fp.c}'s
 * {@code fp_select}.
 * <p>
 * <b>Representation.</b> The C reference uses a 5-limb redundant-radix-51
 * Montgomery form. This Java port stores each field element as a canonical
 * (non-Montgomery, fully reduced) {@link BigInteger} in {@code [0, p)}. The
 * choice trades runtime cost for clarity: every operation is one-line and
 * obviously correct, at the cost of {@link BigInteger}-level allocations per
 * step. The external byte encoding produced by {@link #encode} matches the C
 * {@code fp_encode} byte-for-byte (little-endian 32 bytes), which is the
 * representation that flows through the SQIsign serialised secret key and
 * signature, so any caller observing field elements only at the encoding
 * boundary is identical to the C reference.
 * </p>
 */
final class FpLvl5
{
    /**
     * Prime modulus p = 27 * 2^500 - 1.
     */
    public static final BigInteger P =
        BigInteger.valueOf(27).shiftLeft(500).subtract(BigInteger.ONE);

    /**
     * Byte-length of the canonical little-endian encoding.
     */
    public static final int ENCODED_BYTES = 64;

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger TWO_INV = TWO.modInverse(P);
    private static final BigInteger THREE_INV = BigInteger.valueOf(3).modInverse(P);

    /**
     * Exponent (p+1)/4 used in {@code fp_exp3div4} / square root.
     */
    private static final BigInteger P_PLUS_1_DIV_4 = P.add(BigInteger.ONE).shiftRight(2);

    /**
     * Exponent (p-1)/2 used in {@code fp_is_square}.
     */
    private static final BigInteger P_MINUS_1_DIV_2 = P.subtract(BigInteger.ONE).shiftRight(1);

    // Barrett reduction precomputations. See FpLvl1 for full rationale: a
    // single Barrett step trades one BigInteger.mod (classical division) for
    // two BigInteger.multiply (Karatsuba/Toom) + shift + subtract, which is
    // measurably faster on these 500-bit primes.
    private static final int BARRETT_K = P.bitLength();             // 505
    private static final int BARRETT_SHIFT = 2 * BARRETT_K;
    private static final BigInteger BARRETT_MU =
        BigInteger.ONE.shiftLeft(BARRETT_SHIFT).divide(P);

    private static BigInteger barrettMod(BigInteger x)
    {
        BigInteger q = x.multiply(BARRETT_MU).shiftRight(BARRETT_SHIFT);
        BigInteger r = x.subtract(q.multiply(P));
        if (r.compareTo(P) >= 0)
        {
            r = r.subtract(P);
        }
        if (r.compareTo(P) >= 0)
        {
            r = r.subtract(P);
        }
        if (r.compareTo(P) >= 0)
        {
            // See FpLvl1#barrettMod for the rationale.
            r = r.mod(P);
        }
        return r;
    }

    private FpLvl5()
    {
    }

    // ---- constants ----------------------------------------------------------

    public static Fp zero()
    {
        return new Fp();
    }

    public static Fp one()
    {
        Fp out = new Fp();
        Fp.setOne(out);
        return out;
    }

    public static void setZero(Fp x)
    {
        Fp.setZero(x);
    }

    public static void setOne(Fp x)
    {
        Fp.setOne(x);
    }

    public static void setSmall(Fp x, long val)
    {
        Fp.setSmall(x, val);
    }

    public static void copy(Fp out, Fp a)
    {
        Fp.copy(out, a);
    }

    /** Store a canonical reduced result into {@code out}. */
    private static void writeV(Fp out, BigInteger r)
    {
        out.v = r;
    }

    // ---- arithmetic ---------------------------------------------------------

    public static void add(Fp out, Fp a, Fp b)
    {
        BigInteger r = a.v.add(b.v);
        if (r.compareTo(P) >= 0)
        {
            r = r.subtract(P);
        }
        writeV(out, r);
    }

    public static void sub(Fp out, Fp a, Fp b)
    {
        BigInteger r = a.v.subtract(b.v);
        if (r.signum() < 0)
        {
            r = r.add(P);
        }
        writeV(out, r);
    }

    public static void neg(Fp out, Fp a)
    {
        writeV(out, a.v.signum() == 0 ? BigInteger.ZERO : P.subtract(a.v));
    }

    public static void mul(Fp out, Fp a, Fp b)
    {
        writeV(out, barrettMod(a.v.multiply(b.v)));
    }

    public static void sqr(Fp out, Fp a)
    {
        writeV(out, barrettMod(a.v.multiply(a.v)));
    }

    /**
     * Multiply by a small (unsigned) integer.
     */
    public static void mulSmall(Fp out, Fp a, long val)
    {
        writeV(out, barrettMod(a.v.multiply(BigInteger.valueOf(val))));
    }

    public static void half(Fp out, Fp a)
    {
        writeV(out, barrettMod(a.v.multiply(TWO_INV)));
    }

    public static void div3(Fp out, Fp a)
    {
        writeV(out, barrettMod(a.v.multiply(THREE_INV)));
    }

    public static void inv(Fp x)
    {
        if (x.v.signum() == 0)
        {
            return;
        }
        writeV(x, x.v.modInverse(P));
    }

    /**
     * C reference {@code modpro} — exponent (p - 3)/4.
     */
    public static void progenitor(Fp out, Fp a)
    {
        BigInteger exp = P.subtract(BigInteger.valueOf(3)).shiftRight(2);
        writeV(out, a.v.modPow(exp, P));
    }

    /**
     * Square root of {@code a} in place. Sets {@code a} to a square root of
     * its previous value if one exists; result is undefined (but in [0, p))
     * if {@code a} was not a quadratic residue. Matches {@code fp_sqrt}.
     */
    public static void sqrt(Fp a)
    {
        writeV(a, a.v.modPow(P_PLUS_1_DIV_4, P));
    }

    // ---- predicates ---------------------------------------------------------

    /**
     * @return {@code 0xFFFFFFFF} when {@code a} is a quadratic residue
     * (including zero), {@code 0} otherwise. Matches C
     * {@code fp_is_square}.
     */
    public static int isSquare(Fp a)
    {
        if (a.v.signum() == 0)
        {
            return 0xFFFFFFFF;
        }
        BigInteger leg = a.v.modPow(P_MINUS_1_DIV_2, P);
        return leg.equals(BigInteger.ONE) ? 0xFFFFFFFF : 0;
    }

    public static int isEqual(Fp a, Fp b)
    {
        return Fp.isEqual(a, b);
    }

    public static int isZero(Fp a)
    {
        return Fp.isZero(a);
    }

    // ---- side-channel-shaped helpers ---------------------------------------

    /**
     * {@code ctl} must be {@code 0x00000000} or {@code 0xFFFFFFFF}. Selects
     * {@code a0} when {@code ctl == 0}, {@code a1} when {@code ctl == -1}.
     * Mirrors C {@code fp_select}. The C implementation is bitwise constant-
     * time across the limb array; this Java mirror is functionally equivalent
     * but uses an {@code if} on {@code ctl} since BigInteger arithmetic is
     * not constant-time anyway.
     */
    public static void select(Fp d, Fp a0, Fp a1, int ctl)
    {
        Fp.select(d, a0, a1, ctl);
    }

    // ---- encoding -----------------------------------------------------------

    /**
     * Little-endian 32-byte canonical encoding. Matches C {@code fp_encode}.
     */
    public static void encode(byte[] dst, int off, Fp a)
    {
        BigInteger v = a.v;
        for (int i = 0; i < ENCODED_BYTES; i++)
        {
            dst[off + i] = (byte)(v.intValue() & 0xFF);
            v = v.shiftRight(8);
        }
    }

    public static byte[] encode(Fp a)
    {
        byte[] out = new byte[ENCODED_BYTES];
        encode(out, 0, a);
        return out;
    }

    /**
     * Strict decode: returns {@code 0xFFFFFFFF} iff the input is in canonical
     * range {@code [0, p)} and writes the field element to {@code d}; returns
     * {@code 0} otherwise, leaving {@code d} zeroed (matching C
     * {@code fp_decode}'s "mask to zero on out-of-range" behaviour).
     */
    public static int decode(Fp d, byte[] src, int off)
    {
        BigInteger v = BigInteger.ZERO;
        for (int i = ENCODED_BYTES - 1; i >= 0; i--)
        {
            v = v.shiftLeft(8).or(BigInteger.valueOf(src[off + i] & 0xFFL));
        }
        if (v.compareTo(P) < 0)
        {
            writeV(d, v);
            return 0xFFFFFFFF;
        }
        Fp.setZero(d);
        return 0;
    }

}
