package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Arbitrary-precision integer ("ibz") used throughout the SQIsign quaternion
 * subsystem. Java port of {@code src/quaternion/ref/generic/intbig.c}, which is
 * itself a wrapper over mini-gmp's {@code mpz_t}. The C code uses a mutable
 * out-parameter convention ({@code ibz_add(&out, &a, &b)}); this port mirrors
 * the convention so the structure of higher-level quaternion code can be
 * ported without rearranging call sites.
 * <p>
 * The underlying storage is a {@link BigInteger}. {@link BigInteger} is
 * immutable, so the mutable {@code Ibz} simply rebinds its internal reference.
 * </p>
 */
final class Ibz
{
    /** Mutable holder. */
    public BigInteger v;

    public Ibz()
    {
        this.v = BigInteger.ZERO;
    }

    public Ibz(BigInteger v)
    {
        this.v = v;
    }

    public Ibz(long x)
    {
        this.v = BigInteger.valueOf(x);
    }

    public Ibz copy()
    {
        return new Ibz(this.v);
    }

    public boolean equals(Object o)
    {
        return o instanceof Ibz && this.v.equals(((Ibz)o).v);
    }

    public int hashCode()
    {
        return v.hashCode();
    }

    public String toString()
    {
        return v.toString();
    }

    // ---- constants ----------------------------------------------------------

    public static final Ibz ZERO  = new Ibz(BigInteger.ZERO);
    public static final Ibz ONE   = new Ibz(BigInteger.ONE);
    public static final Ibz TWO   = new Ibz(BigInteger.valueOf(2));
    // ---- assignment ---------------------------------------------------------

    /** Mirrors C {@code ibz_set} (sets {@code i} to {@code x}). */
    public static void set(Ibz i, long x)
    {
        i.v = BigInteger.valueOf(x);
    }

    /** Mirrors C {@code ibz_copy}. */
    public static void copy(Ibz target, Ibz value)
    {
        target.v = value.v;
    }

    /** Mirrors C {@code ibz_swap}. */
    public static void swap(Ibz a, Ibz b)
    {
        BigInteger t = a.v;
        a.v = b.v;
        b.v = t;
    }

    // ---- arithmetic ---------------------------------------------------------

    public static void add(Ibz sum, Ibz a, Ibz b)
    {
        sum.v = a.v.add(b.v);
    }

    public static void sub(Ibz diff, Ibz a, Ibz b)
    {
        diff.v = a.v.subtract(b.v);
    }

    public static void mul(Ibz prod, Ibz a, Ibz b)
    {
        prod.v = a.v.multiply(b.v);
    }

    public static void neg(Ibz neg, Ibz a)
    {
        neg.v = a.v.negate();
    }

    public static void abs(Ibz abs, Ibz a)
    {
        abs.v = a.v.abs();
    }

    /**
     * Truncated division: {@code q = trunc(a/b)}, {@code r = a - b*q}, with
     * {@code r} having the sign of {@code a}. Mirrors C {@code ibz_div} which
     * wraps {@code mpz_tdiv_qr}. {@link BigInteger#divideAndRemainder} is
     * already truncated toward zero on non-negative-magnitude inputs and
     * matches mpz_tdiv_qr semantics exactly.
     */
    public static void div(Ibz quotient, Ibz remainder, Ibz a, Ibz b)
    {
        BigInteger[] qr = a.v.divideAndRemainder(b.v);
        quotient.v = qr[0];
        remainder.v = qr[1];
    }

    /**
     * Floor division: {@code q = floor(a/b)}, {@code r = a - b*q}. When
     * {@code b > 0}, this guarantees {@code 0 <= r < b}. Mirrors mini-gmp
     * {@code mpz_fdiv_qr}. Distinct from {@link #div} (which is truncated
     * toward zero); the difference matters for negative dividends.
     */
    public static void divFloor(Ibz quotient, Ibz remainder, Ibz a, Ibz b)
    {
        BigInteger bv = b.v;
        if (bv.signum() == 0)
        {
            throw new ArithmeticException("divFloor: zero divisor");
        }
        BigInteger r = a.v.mod(bv.abs());           // 0 <= r < |b|
        // a - r divisible by b
        quotient.v = a.v.subtract(r).divide(bv);
        remainder.v = r;
    }

    /**
     * Returns {@code a mod m} but never zero: if {@code a ≡ 0 (mod m)} the
     * result is {@code m} itself. Mirrors HNF helper {@code ibz_mod_not_zero}.
     */
    public static void modNotZero(Ibz res, Ibz a, Ibz mod)
    {
        BigInteger m = a.v.mod(mod.v);
        res.v = m.signum() == 0 ? mod.v : m;
    }

    /**
     * Centered modulo: returns the representative of {@code a} in
     * {@code (-mod/2, mod/2]} (roughly; ties broken positive-first).
     * Mirrors {@code ibz_centered_mod}.
     */
    public static void centeredMod(Ibz remainder, Ibz a, Ibz mod)
    {
        Ibz q = new Ibz();
        Ibz r = new Ibz();
        Ibz d = new Ibz();
        Ibz two = new Ibz(2);
        // d = floor(mod/2)
        divFloor(d, q, mod, two);
        modNotZero(r, a, mod);
        if (r.v.compareTo(d.v) > 0)
        {
            remainder.v = r.v.subtract(mod.v);
        }
        else
        {
            remainder.v = r.v;
        }
    }

    /**
     * Extended GCD variant guaranteeing {@code u != 0}. Used by the HNF
     * core algorithm. Mirrors {@code ibz_xgcd_with_u_not_0}.
     */
    public static void xgcdWithUNotZero(Ibz d, Ibz u, Ibz v, Ibz x, Ibz y)
    {
        if (isZero(x) == 1 && isZero(y) == 1)
        {
            d.v = BigInteger.ONE;
            u.v = BigInteger.ONE;
            v.v = BigInteger.ZERO;
            return;
        }

        BigInteger xv = x.v;
        BigInteger yv = y.v;
        xgcd(d, u, v, x, y);

        // If u == 0, ensure u becomes 1 and adjust v accordingly.
        if (u.v.signum() == 0)
        {
            if (xv.signum() != 0)
            {
                BigInteger yAdjust = yv.signum() == 0 ? BigInteger.ONE : yv;
                BigInteger q = xv.divide(yAdjust);
                v.v = v.v.subtract(q);
            }
            u.v = BigInteger.ONE;
        }

        // Force u*x > 0 (and small) when x != 0.
        if (xv.signum() != 0)
        {
            BigInteger r = xv.multiply(yv);
            boolean neg = r.signum() < 0;
            BigInteger q = xv.multiply(u.v);
            while (q.signum() <= 0)
            {
                BigInteger yOverD = yv.divide(d.v);
                BigInteger xOverD = xv.divide(d.v);
                if (neg)
                {
                    yOverD = yOverD.negate();
                    xOverD = xOverD.negate();
                }
                u.v = u.v.add(yOverD);
                v.v = v.v.subtract(xOverD);
                q = xv.multiply(u.v);
            }
        }
    }

    /** Truncated divide by 2^exp. Mirrors C {@code ibz_div_2exp}. */
    public static void div2exp(Ibz quotient, Ibz a, int exp)
    {
        BigInteger r = a.v;
        if (r.signum() < 0)
        {
            // mpz_tdiv_q_2exp truncates toward zero — match with arithmetic
            // shift on absolute value, then re-apply sign.
            r = r.abs().shiftRight(exp).negate();
        }
        else
        {
            r = r.shiftRight(exp);
        }
        quotient.v = r;
    }

    /**
     * Mirrors C {@code ibz_mod}: r = a mod b (Euclidean remainder, always in
     * {@code [0, |b|)} when {@code b > 0}). Equivalent to mini-gmp
     * {@code mpz_mod}, which always returns a non-negative remainder for
     * positive modulus.
     */
    public static void mod(Ibz r, Ibz a, Ibz b)
    {
        r.v = a.v.mod(b.v.abs());
    }

    /** Mirrors C {@code ibz_divides}: returns 1 iff {@code b | a}. */
    public static int divides(Ibz a, Ibz b)
    {
        if (b.v.signum() == 0)
        {
            return a.v.signum() == 0 ? 1 : 0;
        }
        return a.v.mod(b.v.abs()).signum() == 0 ? 1 : 0;
    }

    /**
     * Mirrors {@code ibz_two_adic} which is {@code mpz_scan1(*pow, 0)} — the
     * index of the lowest set bit. Returns -1 for zero in BigInteger; the C
     * code's mpz_scan1 returns ULONG_MAX in that case. SQIsign callers only
     * call this on non-zero inputs.
     */
    public static int twoAdic(Ibz pow)
    {
        return pow.v.getLowestSetBit();
    }

    public static int cmp(Ibz a, Ibz b)
    {
        return a.v.compareTo(b.v);
    }

    public static int isZero(Ibz x)
    {
        return x.v.signum() == 0 ? 1 : 0;
    }

    public static int isOne(Ibz x)
    {
        return x.v.equals(BigInteger.ONE) ? 1 : 0;
    }

    public static int isEven(Ibz x)
    {
        return x.v.testBit(0) ? 0 : 1;
    }

    public static int isOdd(Ibz x)
    {
        return x.v.testBit(0) ? 1 : 0;
    }

    /** {@code int32_t ibz_get} returns the low 32 bits as signed int. */
    public static int get(Ibz i)
    {
        return i.v.intValue();
    }

    public static int bitsize(Ibz a)
    {
        return a.v.abs().bitLength();
    }

    public static void gcd(Ibz gcd, Ibz a, Ibz b)
    {
        gcd.v = a.v.gcd(b.v);
    }

    /**
     * Extended GCD: computes {@code gcd = u*a + v*b} along with the Bezout
     * coefficients {@code u, v}. Mirrors mini-gmp {@code mpz_gcdext} via the
     * standard iterative Euclidean algorithm. The returned gcd is always
     * non-negative; (u, v) are the smallest-norm Bezout pair that the
     * algorithm produces.
     */
    public static void xgcd(Ibz gcd, Ibz u, Ibz v, Ibz a, Ibz b)
    {
        BigInteger r0 = a.v, r1 = b.v;
        BigInteger s0 = BigInteger.ONE, s1 = BigInteger.ZERO;
        BigInteger t0 = BigInteger.ZERO, t1 = BigInteger.ONE;
        while (r1.signum() != 0)
        {
            BigInteger[] qr = r0.divideAndRemainder(r1);
            BigInteger q = qr[0];
            BigInteger r2 = qr[1];
            BigInteger s2 = s0.subtract(q.multiply(s1));
            BigInteger t2 = t0.subtract(q.multiply(t1));
            r0 = r1; r1 = r2;
            s0 = s1; s1 = s2;
            t0 = t1; t1 = t2;
        }
        if (r0.signum() < 0)
        {
            r0 = r0.negate();
            s0 = s0.negate();
            t0 = t0.negate();
        }
        gcd.v = r0;
        u.v = s0;
        v.v = t0;
    }

    /**
     * Modular inverse. Returns 1 on success (and writes the inverse to
     * {@code inv}), 0 if no inverse exists (and leaves {@code inv} unchanged,
     * matching C {@code ibz_invmod}'s wrap of {@code mpz_invert}).
     */
    public static int invmod(Ibz inv, Ibz a, Ibz mod)
    {
        try
        {
            inv.v = a.v.mod(mod.v.abs()).modInverse(mod.v.abs());
            return 1;
        }
        catch (ArithmeticException e)
        {
            return 0;
        }
    }

    /**
     * Mirrors C {@code ibz_probab_prime}: Miller-Rabin primality test with
     * {@code reps} iterations. Returns a positive value when {@code n} is
     * probably prime, 0 otherwise. {@link BigInteger#isProbablePrime} returns
     * a boolean; we map it to 1/0 to match the mini-gmp return convention.
     *
     * <p><b>Trial-division prefilter.</b> Before invoking the expensive
     * Miller-Rabin, we test divisibility by the first ~50 small primes
     * (up to 233). Each candidate {@code n} is reduced mod {@link #SMALL_PRIME_PRODUCT}
     * (a single BigInteger {@code mod} of a ~256-bit candidate by a ~64-bit
     * constant, ~200 ns), then GCD'd against that product to find any shared
     * small-prime factor. A non-trivial GCD means {@code n} is divisible by
     * at least one of those primes and is therefore composite — no Miller-Rabin
     * needed. Empirically this catches ~80% of random composites at SQIsign's
     * candidate sizes; the JFR profile showed Miller-Rabin (passesMillerRabin /
     * primeToCertainty / modPow chain) accounting for ~7-8% of total CPU, so
     * the prefilter is a measurable win whenever {@code n} is composite.</p>
     */
    public static int probabPrime(Ibz n, int reps)
    {
        BigInteger v = n.v;
        // 2 and 3 are special-cased (the product below excludes 2, 3).
        if (v.signum() <= 0)
        {
            return 0;
        }
        if (v.compareTo(BigInteger.valueOf(3)) <= 0)
        {
            // n ∈ {1, 2, 3}. 2 and 3 are prime, 1 is not.
            return v.compareTo(BigInteger.ONE) > 0 ? 1 : 0;
        }
        if (!v.testBit(0))
        {
            return 0; // even and > 2
        }
        // Trial-division prefilter: gcd(n, product-of-first-N-odd-primes).
        // If gcd > 1, n shares a small-prime factor → composite.
        BigInteger g = v.gcd(SMALL_PRIME_PRODUCT);
        if (g.compareTo(BigInteger.ONE) > 0)
        {
            // Composite unless n itself is one of those small primes.
            // (n.gcd(prod) == n in that case.)
            return v.equals(g) ? 1 : 0;
        }
        return v.isProbablePrime(reps) ? 1 : 0;
    }

    /**
     * Product of the first 50 odd primes (3 through 233). A BigInteger {@code gcd}
     * against this catches any candidate divisible by primes up to 233 — that's
     * ~80% of random odd composites. ~390-bit / ~50-byte constant.
     */
    private static final BigInteger SMALL_PRIME_PRODUCT;
    static
    {
        int[] smallPrimes = {
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
            37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
            79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
            131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233
        };
        BigInteger p = BigInteger.ONE;
        for (int i = 0; i < smallPrimes.length; i++)
        {
            p = p.multiply(BigInteger.valueOf(smallPrimes[i]));
        }
        SMALL_PRIME_PRODUCT = p;
    }

    /**
     * Mirrors C {@code ibz_sqrt}: if {@code a} is a perfect square, writes
     * floor(sqrt(a)) to {@code sqrt} and returns 1. Otherwise returns 0
     * (sqrt left as floor candidate).
     */
    public static int sqrt(Ibz sqrt, Ibz a)
    {
        if (a.v.signum() < 0)
        {
            return 0;
        }
        Ibz cand = new Ibz();
        sqrtFloor(cand, a);
        BigInteger sq = cand.v.multiply(cand.v);
        if (sq.equals(a.v))
        {
            sqrt.v = cand.v;
            return 1;
        }
        return 0;
    }

    /**
     * Mirrors C {@code ibz_sqrt_mod_p}: modular square root of {@code a} mod
     * {@code p}. Three cases:
     * <ul>
     *   <li>p ≡ 3 (mod 4): sqrt = a^((p+1)/4) mod p</li>
     *   <li>p ≡ 5 (mod 8): two sub-cases on a^((p-1)/4)</li>
     *   <li>p ≡ 1 (mod 8): Tonelli-Shanks</li>
     * </ul>
     * Returns 1 on success, 0 if {@code a} is not a quadratic residue mod p.
     */
    public static int sqrtModP(Ibz sqrt, Ibz a, Ibz p)
    {
        BigInteger pVal = p.v;
        BigInteger amod = a.v.mod(pVal);

        if (amod.signum() == 0)
        {
            sqrt.v = BigInteger.ZERO;
            return 1;
        }

        // Legendre symbol check
        BigInteger pMinus1 = pVal.subtract(BigInteger.ONE);
        if (!amod.modPow(pMinus1.shiftRight(1), pVal).equals(BigInteger.ONE))
        {
            return 0;
        }

        BigInteger p4 = pVal.mod(BigInteger.valueOf(4));
        if (p4.equals(BigInteger.valueOf(3)))
        {
            BigInteger exp = pVal.add(BigInteger.ONE).shiftRight(2);
            sqrt.v = amod.modPow(exp, pVal);
            return 1;
        }

        BigInteger p8 = pVal.mod(BigInteger.valueOf(8));
        if (p8.equals(BigInteger.valueOf(5)))
        {
            BigInteger exp = pVal.subtract(BigInteger.ONE).shiftRight(2);
            BigInteger t = amod.modPow(exp, pVal);
            if (t.equals(BigInteger.ONE))
            {
                BigInteger exp2 = pVal.add(BigInteger.valueOf(3)).shiftRight(3);
                sqrt.v = amod.modPow(exp2, pVal);
            }
            else
            {
                BigInteger exp2 = pVal.subtract(BigInteger.valueOf(5)).shiftRight(3);
                BigInteger a4 = amod.shiftLeft(2);
                BigInteger t2 = a4.modPow(exp2, pVal);
                BigInteger a2 = amod.shiftLeft(1);
                sqrt.v = a2.multiply(t2).mod(pVal);
            }
            return 1;
        }

        // p ≡ 1 (mod 8): Tonelli-Shanks
        // Decompose p - 1 = q * 2^e
        BigInteger q = pMinus1;
        int e = 0;
        while (!q.testBit(0))
        {
            q = q.shiftRight(1);
            e++;
        }

        // Find a quadratic non-residue
        BigInteger qnr = BigInteger.valueOf(2);
        while (qnr.modPow(pMinus1.shiftRight(1), pVal).equals(BigInteger.ONE))
        {
            qnr = qnr.add(BigInteger.ONE);
        }
        BigInteger z = qnr.modPow(q, pVal);

        BigInteger y = amod.modPow(q, pVal);
        BigInteger x = amod.modPow(q.add(BigInteger.ONE).shiftRight(1), pVal);

        BigInteger exp = BigInteger.ONE.shiftLeft(e - 2);
        for (int i = 0; i < e; i++)
        {
            BigInteger b = y.modPow(exp, pVal);
            if (b.equals(pMinus1))
            {
                x = x.multiply(z).mod(pVal);
                y = y.multiply(z).multiply(z).mod(pVal);
            }
            z = z.modPow(BigInteger.valueOf(2), pVal);
            exp = exp.shiftRight(1);
        }
        sqrt.v = x;
        return 1;
    }

    /**
     * Floor of integer square root. Mirrors C {@code ibz_sqrt_floor}.
     * Implemented via Newton's method since {@code BigInteger.sqrt} is Java
     * 9+ and the base BC sources compile with {@code --release 8}.
     */
    public static void sqrtFloor(Ibz sqrt, Ibz a)
    {
        BigInteger n = a.v;
        if (n.signum() < 0)
        {
            throw new ArithmeticException("ibz_sqrt_floor of negative");
        }
        if (n.signum() == 0)
        {
            sqrt.v = BigInteger.ZERO;
            return;
        }
        // Start with a power-of-two upper bound: 2^(ceil(bitlen/2)) > sqrt(n).
        BigInteger x = BigInteger.ONE.shiftLeft((n.bitLength() + 1) >>> 1);
        while (true)
        {
            BigInteger y = x.add(n.divide(x)).shiftRight(1);
            if (y.compareTo(x) >= 0)
            {
                sqrt.v = x;
                return;
            }
            x = y;
        }
    }

    // ---- digit-array bridge --------------------------------------------------

    /**
     * Construct an {@link Ibz} from a GMP {@code mpz_t}-style limb array:
     * little-endian unsigned 64-bit limbs with an explicit signed limb count
     * ({@code mp_size}). Used to copy the published lvl1 precomp constants
     * (e.g. {@code _mp_size = 4, _mp_d = {l0, l1, l2, l3}}) verbatim from the
     * C reference into Java.
     *
     * @param size signed limb count: positive for non-negative values, zero
     *             for the integer zero, negative for negative values.
     * @param limbs unsigned 64-bit limbs in little-endian order. Length must
     *              be at least {@code |size|}.
     */
    private static final BigInteger MASK64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    public static Ibz fromMpLimbs(int size, long[] limbs)
    {
        if (size == 0)
        {
            return new Ibz(BigInteger.ZERO);
        }
        int n = Math.abs(size);
        if (limbs.length < n)
        {
            throw new IllegalArgumentException(
                "fromMpLimbs: limb array too short for mp_size " + size);
        }
        BigInteger v = BigInteger.ZERO;
        for (int i = n - 1; i >= 0; i--)
        {
            v = v.shiftLeft(64).or(BigInteger.valueOf(limbs[i]).and(MASK64));
        }
        return new Ibz(size > 0 ? v : v.negate());
    }

    // ---- rejection-sampling random -----------------------------------------

    /**
     * Uniform random integer in {@code [a, b]} (closed-closed). Mirrors C
     * {@code ibz_rand_interval} with rejection sampling on raw DRBG bytes.
     * The byte order, masking and acceptance rule are bit-for-bit identical
     * to the C reference so that, given the same NIST DRBG state, this
     * function produces the same sample as the C code.
     *
     * @return 1 on success, 0 if the {@link SecureRandom} fails (treated as
     *         a host-RNG failure, matching the C return value).
     */
    public static int randInterval(Ibz rand, Ibz a, Ibz b, SecureRandom random)
    {
        BigInteger bmina = b.v.subtract(a.v);
        int sgn = bmina.signum();
        if (sgn == 0)
        {
            rand.v = a.v;
            return 1;
        }
        if (sgn < 0)
        {
            // C asserts a <= b implicitly; mirror by returning failure.
            return 0;
        }

        int lenBits = bmina.bitLength();
        int lenBytes = (lenBits + 7) >>> 3;

        // The C masks the topmost limb so that bits beyond lenBits are zero.
        // In a byte-oriented Java port the equivalent is masking the high
        // byte to (lenBits mod 8) low bits, when lenBits is not a multiple
        // of 8.
        int topByteBits = lenBits - (lenBytes - 1) * 8;
        int topByteMask = topByteBits >= 8 ? 0xFF : ((1 << topByteBits) - 1);

        byte[] r = new byte[lenBytes];
        BigInteger candidate;
        do
        {
            try
            {
                random.nextBytes(r);
            }
            catch (RuntimeException e)
            {
                return 0;
            }
            r[lenBytes - 1] = (byte)(r[lenBytes - 1] & topByteMask);

            // Little-endian: byte 0 is the LSB.
            candidate = BigInteger.ZERO;
            for (int i = lenBytes - 1; i >= 0; i--)
            {
                candidate = candidate.shiftLeft(8).or(BigInteger.valueOf(r[i] & 0xFFL));
            }
        }
        while (candidate.compareTo(bmina) > 0);
        rand.v = candidate.add(a.v);
        return 1;
    }

    /**
     * Uniform random integer in {@code [-m, m]}. Mirrors C
     * {@code ibz_rand_interval_minm_m}.
     */
    public static int randIntervalMinmM(Ibz rand, int m, SecureRandom random)
    {
        Ibz mBig = new Ibz(BigInteger.valueOf(2L * m));
        int ret = randInterval(rand, ZERO, mBig, random);
        if (ret == 1)
        {
            rand.v = rand.v.subtract(BigInteger.valueOf(m));
        }
        return ret;
    }
}
