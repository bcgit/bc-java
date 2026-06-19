package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * "Double Plus Exponent" floating-point arithmetic — a value is stored as
 * {@code mantissa * 2^exponent} where {@code mantissa} ∈ [0.5, 1.0) (or
 * exactly 0 when the value is zero) and {@code exponent} is a signed integer.
 *
 * <p>Mirrors the subset of the DPE library used by SQIsign's LLL: this
 * provides ~53 bits of mantissa precision with unbounded exponent range,
 * matching {@code dpe_t} configured to use {@code DPE_USE_DOUBLE}.</p>
 */
final class Dpe
{
    /** Mantissa in [0.5, 1.0) when nonzero; exactly 0.0 when zero. */
    public double mantissa;
    /** Exponent; arbitrary when value is zero (canonicalised to 0). */
    public int exponent;

    public Dpe()
    {
        this.mantissa = 0.0;
        this.exponent = 0;
    }

    public Dpe(Dpe other)
    {
        this.mantissa = other.mantissa;
        this.exponent = other.exponent;
    }

    // ---- assignment ---------------------------------------------------------

    /** Mirrors {@code dpe_set}. */
    public static void set(Dpe dst, Dpe src)
    {
        dst.mantissa = src.mantissa;
        dst.exponent = src.exponent;
    }

    /** Mirrors {@code dpe_set_d}. */
    public static void setD(Dpe dst, double d)
    {
        if (d == 0.0)
        {
            dst.mantissa = 0.0;
            dst.exponent = 0;
        }
        else
        {
            int e = getExponent(d);
            int shift = -(e + 1);
            dst.mantissa = scalb(d, shift);
            dst.exponent = -shift;
        }
    }

    /**
     * Mirrors {@code dpe_set_z} (which is built on GMP's {@code mpz_get_d_2exp}):
     * set from a {@link BigInteger}. Captures the top ~53 bits as mantissa and
     * the remaining bit-length as exponent. GMP's {@code mpz_get_d_2exp}
     * documents truncation (round-toward-zero) of the discarded low bits, so
     * we mirror that: {@code shiftRight} drops the low bits without rounding.
     */
    public static void setZ(Dpe dst, Ibz z)
    {
        BigInteger v = z.v;
        int sign = v.signum();
        if (sign == 0)
        {
            dst.mantissa = 0.0;
            dst.exponent = 0;
            return;
        }
        BigInteger a = v.abs();
        int bitlen = a.bitLength();
        BigInteger top;
        int shift;
        if (bitlen > 53)
        {
            shift = bitlen - 53;
            top = a.shiftRight(shift);
        }
        else
        {
            shift = 0;
            top = a;
        }
        double m = top.doubleValue();
        // m ∈ [2^52, 2^53), normalise to [0.5, 1) and accumulate the
        // exponent offset.
        int e = getExponent(m);
        int extraShift = -(e + 1);
        dst.mantissa = scalb(m, extraShift);
        dst.exponent = shift - extraShift;
        if (sign < 0)
        {
            dst.mantissa = -dst.mantissa;
        }
    }

    /**
     * Mirrors {@code dpe_get_z}: round to nearest integer and return as Ibz.
     *
     * <p>Critical edge case: when {@code |x|} exceeds {@code 2^63}, the
     * scaled value overflows {@code long}, and naive {@code Math.round}
     * saturates at {@code Long.MAX_VALUE} — silently corrupting the result.
     * This destroys LLL's size-reduction inner loop because the
     * "subtract X · b_i" step under-corrects, leaving {@code |u|} above
     * the {@code ETABAR} threshold and causing the size-reduction while-loop
     * to spin forever.</p>
     *
     * <p>To match the C reference faithfully we split into three regimes:</p>
     * <ul>
     *   <li>{@code exponent < 0}: {@code |x| < 1/2}, round to zero.</li>
     *   <li>{@code 0 <= exponent < 53}: compute {@code mantissa · 2^exponent}
     *       as a double, round, convert to BigInteger (always fits in a
     *       long since the double's magnitude is below {@code 2^53}).</li>
     *   <li>{@code exponent >= 53}: the value is already an integer.
     *       Compute {@code mantissa · 2^53} as a double (still fits in a long
     *       since the mantissa is in [0.5, 1)), convert to BigInteger,
     *       then shift left by {@code exponent - 53}. Mirrors the C
     *       {@code mpz_set_d} + {@code mpz_mul_2exp} path.</li>
     * </ul>
     */
    public static void getZ(Ibz dst, Dpe x)
    {
        if (x.mantissa == 0.0)
        {
            dst.v = BigInteger.ZERO;
            return;
        }
        if (x.exponent < 0)
        {
            // |x| < 1/2 → round to zero.
            dst.v = BigInteger.ZERO;
            return;
        }
        if (x.exponent < 53)
        {
            // mantissa · 2^exponent fits in a double < 2^53, exact long.
            // Match C dpe_get_z: round half-away-from-zero (mirrors libc
            // round()), via floor/ceil + frac to avoid losing precision when
            // scaled is near the upper end of its representable range.
            double scaled = scalb(x.mantissa, x.exponent);
            double rounded;
            if (scaled >= 0.0)
            {
                double f = Math.floor(scaled);
                double frac = scaled - f;
                rounded = frac >= 0.5 ? f + 1.0 : f;
            }
            else
            {
                double c = Math.ceil(scaled);
                double frac = c - scaled;
                rounded = frac >= 0.5 ? c - 1.0 : c;
            }
            dst.v = BigInteger.valueOf((long)rounded);
            return;
        }
        // exponent >= 53: value is already an integer; compute via the C
        // reference's split form to avoid long saturation.
        // shifted = mantissa · 2^53 (an integer in [2^52, 2^53) by magnitude).
        double shifted = scalb(x.mantissa, 53);
        long top = (long)shifted;
        dst.v = BigInteger.valueOf(top).shiftLeft(x.exponent - 53);
    }

    // ---- arithmetic ---------------------------------------------------------

    public static void mul(Dpe dst, Dpe a, Dpe b)
    {
        if (a.mantissa == 0.0 || b.mantissa == 0.0)
        {
            dst.mantissa = 0.0;
            dst.exponent = 0;
            return;
        }
        double m = a.mantissa * b.mantissa;
        int e = a.exponent + b.exponent;
        // m is in [0.25, 1) (since each factor is in [0.5,1)). Renormalise.
        int eAdj = getExponent(m);
        int shift = -(eAdj + 1);
        dst.mantissa = scalb(m, shift);
        dst.exponent = e - shift;
    }

    public static void add(Dpe dst, Dpe a, Dpe b)
    {
        if (a.mantissa == 0.0)
        {
            set(dst, b);
            return;
        }
        if (b.mantissa == 0.0)
        {
            set(dst, a);
            return;
        }
        int diff = a.exponent - b.exponent;
        double m;
        int e;
        if (diff >= 0)
        {
            // align b to a's exponent
            if (diff > 53)
            {
                set(dst, a);
                return;
            }
            m = a.mantissa + scalb(b.mantissa, -diff);
            e = a.exponent;
        }
        else
        {
            int d = -diff;
            if (d > 53)
            {
                set(dst, b);
                return;
            }
            m = b.mantissa + scalb(a.mantissa, -d);
            e = b.exponent;
        }
        if (m == 0.0)
        {
            dst.mantissa = 0.0;
            dst.exponent = 0;
            return;
        }
        int eAdj = getExponent(m);
        int shift = -(eAdj + 1);
        dst.mantissa = scalb(m, shift);
        dst.exponent = e - shift;
    }

    public static void sub(Dpe dst, Dpe a, Dpe b)
    {
        Dpe neg = new Dpe(b);
        neg.mantissa = -neg.mantissa;
        add(dst, a, neg);
    }

    public static void div(Dpe dst, Dpe a, Dpe b)
    {
        if (b.mantissa == 0.0)
        {
            throw new ArithmeticException("dpe div by zero");
        }
        if (a.mantissa == 0.0)
        {
            dst.mantissa = 0.0;
            dst.exponent = 0;
            return;
        }
        double m = a.mantissa / b.mantissa;
        int e = a.exponent - b.exponent;
        int eAdj = getExponent(m);
        int shift = -(eAdj + 1);
        dst.mantissa = scalb(m, shift);
        dst.exponent = e - shift;
    }

    public static void abs(Dpe dst, Dpe a)
    {
        dst.mantissa = Math.abs(a.mantissa);
        dst.exponent = a.exponent;
    }

    /**
     * Round to nearest integer (in dpe representation). Mirrors {@code dpe_round}
     * which uses {@code round()} semantics: round to nearest, ties away from zero.
     * Java's {@code Math.rint} rounds half-to-even and Java's {@code Math.round}
     * rounds half toward positive infinity — both differ from C's behaviour at
     * exact half-way values, which can flip LLL swap decisions.
     *
     * <p>The implementation uses {@code frac = scaled - floor(scaled)} instead of
     * {@code floor(scaled + 0.5)}: the addition can lose precision near the
     * fraction's representation limit (e.g. {@code 0.5 - ε + 0.5} can round to
     * {@code 1.0}, then {@code floor} yields 1, but the correct round is 0).
     * The {@code floor + frac} form is exact when scaled is in normal range.</p>
     */
    public static void round(Dpe dst, Dpe a)
    {
        if (a.mantissa == 0.0)
        {
            dst.mantissa = 0.0;
            dst.exponent = 0;
            return;
        }
        double scaled = scalb(a.mantissa, a.exponent);
        // If scaled is way larger than long range, leave it as-is (integer already).
        if (a.exponent > 52)
        {
            set(dst, a);
            return;
        }
        // C's round(): ties away from zero. Exact decomposition into integer
        // floor/ceil and fractional part to avoid the v+0.5 precision pitfall.
        double rounded;
        if (scaled >= 0.0)
        {
            double f = Math.floor(scaled);
            double frac = scaled - f;
            rounded = frac >= 0.5 ? f + 1.0 : f;
        }
        else
        {
            double c = Math.ceil(scaled);
            double frac = c - scaled;
            rounded = frac >= 0.5 ? c - 1.0 : c;
        }
        setD(dst, rounded);
    }

    // ---- comparison ---------------------------------------------------------

    public static int cmp(Dpe a, Dpe b)
    {
        // First handle zeros.
        int sA = Double.compare(a.mantissa, 0.0);
        int sB = Double.compare(b.mantissa, 0.0);
        if (sA == 0 && sB == 0)
        {
            return 0;
        }
        if (sA == 0)
        {
            return -sB;
        }
        if (sB == 0)
        {
            return sA;
        }
        // Different signs → compare signs.
        if ((a.mantissa > 0) != (b.mantissa > 0))
        {
            return a.mantissa > 0 ? 1 : -1;
        }
        // Same sign. Compare magnitudes (account for sign in the end).
        boolean negative = a.mantissa < 0;
        if (a.exponent != b.exponent)
        {
            int eCmp = a.exponent < b.exponent ? -1 : 1;
            return negative ? -eCmp : eCmp;
        }
        return Double.compare(a.mantissa, b.mantissa);
    }

    /** Mirrors {@code dpe_cmp_d}. */
    public static int cmpD(Dpe a, double d)
    {
        Dpe tmp = new Dpe();
        setD(tmp, d);
        return cmp(a, tmp);
    }

    // ---- JDK 1.5 fallbacks for java.lang.Math.getExponent / Math.scalb ------
    // Those methods were added in JDK 1.6; the jdk15to18 distribution must run
    // on a genuine JRE 5. These reproduce them bit-for-bit (getExponent by the
    // IEEE-754 exponent field; scalb by the faithful OpenJDK power-of-two-split
    // algorithm) so the SQIsign DPE arithmetic is numerically identical.

    private static final long EXP_BIT_MASK = 0x7ff0000000000000L;

    private static int getExponent(double d)
    {
        return (int)(((Double.doubleToRawLongBits(d) & EXP_BIT_MASK) >> 52) - 1023L);
    }

    private static double powerOfTwoD(int n)
    {
        return Double.longBitsToDouble((((long)n + 1023L) << 52) & EXP_BIT_MASK);
    }

    private static double scalb(double d, int scaleFactor)
    {
        // Double.MAX_EXPONENT + -Double.MIN_EXPONENT + SIGNIFICAND_WIDTH + 1
        final int MAX_SCALE = 1023 + 1022 + 53 + 1;
        int scale_increment;
        double exp_delta;
        if (scaleFactor < 0)
        {
            scaleFactor = Math.max(scaleFactor, -MAX_SCALE);
            scale_increment = -512;
            exp_delta = powerOfTwoD(-512);
        }
        else
        {
            scaleFactor = Math.min(scaleFactor, MAX_SCALE);
            scale_increment = 512;
            exp_delta = powerOfTwoD(512);
        }

        // Calculate (scaleFactor % +/-512) per Hacker's Delight 10-2.
        int t = (scaleFactor >> (9 - 1)) >>> (32 - 9);
        int exp_adjust = ((scaleFactor + t) & (512 - 1)) - t;

        d *= powerOfTwoD(exp_adjust);
        scaleFactor -= exp_adjust;

        while (scaleFactor != 0)
        {
            d *= exp_delta;
            scaleFactor -= scale_increment;
        }
        return d;
    }

}
