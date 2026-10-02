package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;

/**
 * Element of F_p12 = F_p4[w]/(w^3 - v), i.e. w^3 = v, for SM9 (GM/T 0044.5-2016,
 * 1-2-4-12 tower). This is the pairing target group G_T. Written a + b*w + c*w^2
 * with a the low and c the high (w^2-coefficient) dimension, a, b, c in
 * {@link Fp4}. Immutable: its ninety-six limbs, a's, b's and then c's, are not changed once it is
 * made.
 * <p>
 * The arithmetic is {@link Fp}'s, on fixed-width limbs, and runs the same instructions whatever the
 * values it is given; the static methods compute on elements held in int arrays, as {@link Fp4}'s
 * do. The products and squares form the products in F_q their formulas call for in full, as wide
 * values - see {@link Fp#WIDE} - add and subtract them into each of the twelve coefficients of their
 * result unreduced, and reduce each coefficient once.
 */
public class Fp12
{
    static final int SIZE = 3 * Fp4.SIZE;
    static final int MUL_SCRATCH = 25 * Fp.WIDE + 2 * Fp4.SIZE + Fp4.MUL_WIDE_SCRATCH;
    static final int SQR_SCRATCH = 21 * Fp.WIDE + Fp4.SIZE + Fp4.MUL_WIDE_SCRATCH;
    static final int CYCLOTOMIC_SQR_SCRATCH = 25 * Fp.WIDE + Fp4.SQR_WIDE_SCRATCH;
    static final int MUL_SPARSE_SCRATCH = 21 * Fp.WIDE + 2 * Fp4.SIZE + Fp4.MUL_WIDE_SCRATCH;
    static final int COMPRESSED_SIZE = 4 * Fp2.SIZE;
    static final int COMPRESSED_SQR_SCRATCH = 17 * Fp.WIDE + 2 * Fp2.SIZE + Fp2.MUL_WIDE_SCRATCH;

    static final Fp12 ONE = new Fp12(Fp4.ONE, Fp4.ZERO, Fp4.ZERO);

    final int[] limbs;

    // the tables powSecureFixedBase reads, made from this element on the first call and kept - see
    // combTables()
    private volatile int[][] combTables;

    Fp12(Fp4 a, Fp4 b, Fp4 c)
    {
        limbs = new int[SIZE];
        System.arraycopy(a.limbs, 0, limbs, 0, Fp4.SIZE);
        System.arraycopy(b.limbs, 0, limbs, Fp4.SIZE, Fp4.SIZE);
        System.arraycopy(c.limbs, 0, limbs, 2 * Fp4.SIZE, Fp4.SIZE);
    }

    Fp12(int[] limbs)
    {
        this.limbs = limbs;
    }

//    Fp12 add(Fp12 o)
//    {
//        int[] z = new int[SIZE];
//        for (int i = 0; i < SIZE; i += Fp4.SIZE)
//        {
//            Fp4.add(limbs, i, o.limbs, i, z, i);
//        }
//        return new Fp12(z);
//    }

//    Fp12 subtract(Fp12 o)
//    {
//        int[] z = new int[SIZE];
//        for (int i = 0; i < SIZE; i += Fp4.SIZE)
//        {
//            Fp4.sub(limbs, i, o.limbs, i, z, i);
//        }
//        return new Fp12(z);
//    }

//    Fp12 negate()
//    {
//        int[] z = new int[SIZE];
//        for (int i = 0; i < SIZE; i += Fp.SIZE)
//        {
//            Fp.neg(limbs, i, z, i);
//        }
//        return new Fp12(z);
//    }

    public Fp12 multiply(Fp12 o)
    {
        return multiply(o, new int[MUL_SCRATCH]);
    }

    // this * o on the scratch t, of MUL_SCRATCH limbs, which a caller taking one product or square
    // after another makes once for all of them
    Fp12 multiply(Fp12 o, int[] t)
    {
        int[] z = new int[SIZE];
        mul(limbs, 0, o.limbs, 0, z, 0, t, 0);
        return new Fp12(z);
    }

//    /**
//     * this * (l0 + l2 w^2) for l0 in F_p4 and l2 in F_p2, the shape of the Miller loop's line
//     * values, which have neither a w term nor a v w^2 term - see {@link #mulSparse}.
//     */
//    Fp12 multiplySparse(Fp4 l0, Fp2 l2)
//    {
//        int[] z = new int[SIZE];
//        mulSparse(limbs, 0, l0.limbs, 0, l2.limbs, 0, z, 0, new int[MUL_SPARSE_SCRATCH], 0);
//        return new Fp12(z);
//    }

//    Fp12 square()
//    {
//        int[] z = new int[SIZE];
//        sqr(limbs, 0, z, 0, new int[SQR_SCRATCH], 0);
//        return new Fp12(z);
//    }

    /**
     * The square of an element of the cyclotomic subgroup, the subgroup of F_p12^* of order
     * q^4 - q^2 + 1, which holds G_T and the (q^6 - 1)(q^2 + 1)-th power of every non-zero element -
     * so every value the final exponentiation goes on to exponentiate. There, by Granger and Scott's
     * formula,
     * (a + b w + c w^2)^2 = (3a^2 - 2 conj(a)) + (3c^2 v + 2 conj(b)) w + (3b^2 - 2 conj(c)) w^2,
     * where conj(x + y v) = x - y v is the q^2-power Frobenius of F_p4: three F_p4 squarings where
     * {@link #sqr} takes two F_p4 products and three squarings. For any other element - one of
     * order dividing q^6 + 1, as f^(q^6 - 1) is, included - the result is not its square, so
     * {@link #sqr} stays the general squaring the Miller loop needs.
     */
    Fp12 cyclotomicSquare()
    {
        return cyclotomicSquare(new int[CYCLOTOMIC_SQR_SCRATCH]);
    }

    // cyclotomicSquare() on the scratch t, of CYCLOTOMIC_SQR_SCRATCH limbs - see multiply(Fp12, int[])
    Fp12 cyclotomicSquare(int[] t)
    {
        int[] z = new int[SIZE];
        cyclotomicSqr(limbs, 0, null, 0, z, 0, t, 0);
        return new Fp12(z);
    }

//    /**
//     * The square of this element when it is m y, for y in the cyclotomic subgroup and m a non-zero
//     * element of F_q, given as {@link Fp} holds one - the form in which {@link #powSecure} carries
//     * its running values. It is m^2 y^2, and Granger and Scott's formula for y^2 gives it in the
//     * coefficients a, b and c of m y as
//     * (3a^2 - 2m conj(a)) + (3c^2 v + 2m conj(b)) w + (3b^2 - 2m conj(c)) w^2, conj being F_q-linear:
//     * {@link #cyclotomicSquare()}'s three F_p4 squarings and twelve products by m. The formula
//     * without the m would not give it, since m y is not in the subgroup.
//     */
//    Fp12 cyclotomicSquare(int[] m)
//    {
//        int[] z = new int[SIZE];
//        cyclotomicSqr(limbs, 0, m, 0, z, 0, new int[CYCLOTOMIC_SQR_SCRATCH], 0);
//        return new Fp12(z);
//    }

//    /**
//     * This element times s, an element of F_q given as {@link Fp} holds one: each of its twelve
//     * coefficients times s.
//     */
//    Fp12 scale(int[] s)
//    {
//        int[] z = new int[SIZE];
//        for (int i = 0; i < SIZE; i += Fp.SIZE)
//        {
//            Fp.mul(limbs, i, s, 0, z, i);
//        }
//        return new Fp12(z);
//    }

    /**
     * The coefficient of w^i, i being 0, 1 or 2.
     */
    Fp4 coefficient(int i)
    {
        return new Fp4(Arrays.copyOfRange(limbs, i * Fp4.SIZE, (i + 1) * Fp4.SIZE));
    }

    Fp12 invert()
    {
        // cubic extension inverse, L = F_p4[w]/(w^3 - gamma), gamma = v:
        //   t0 = a^2 - gamma*b*c ; t1 = gamma*c^2 - a*b ; t2 = b^2 - a*c
        //   norm = a*t0 + gamma*(b*t2 + c*t1) ;  inv = (t0 + t1 w + t2 w^2)/norm
        Fp4 a = coefficient(0), b = coefficient(1), c = coefficient(2);
        Fp4 t0 = a.square().subtract(b.multiply(c).mulV());
        Fp4 t1 = c.square().mulV().subtract(a.multiply(b));
        Fp4 t2 = b.square().subtract(a.multiply(c));
        Fp4 norm = a.multiply(t0).add(b.multiply(t2).add(c.multiply(t1)).mulV());
        Fp4 ni = norm.invert();
        return new Fp12(t0.multiply(ni), t1.multiply(ni), t2.multiply(ni));
    }

    /**
     * Variable-time exponentiation, for PUBLIC exponents only; the pairing's final exponentiation
     * does not call it, raising to the BN parameter t through a chain of its own. For secret
     * exponents use {@link #powSecure}. The base must lie in the cyclotomic subgroup, as G_T and
     * every value the final exponentiation exponentiates do, since the squaring is
     * {@link #cyclotomicSquare}.
     */
    public Fp12 pow(BigInteger e)
    {
        if (e.signum() < 0)
        {
            // the loop reads e's bits and so took a negative exponent as its magnitude, returning
            // x^|e| where x^-|e| was asked for. No in-tree call site passes one; this is for the
            // exported method.
            throw new IllegalArgumentException("exponent must be non-negative");
        }
        Fp12 r = ONE;
        Fp12 b = this;
        int[] t = new int[MUL_SCRATCH];
        int n = e.bitLength();
        for (int i = 0; i < n; ++i)
        {
            if (e.testBit(i))
            {
                r = r.multiply(b, t);
            }
            b = b.cyclotomicSquare(t);
        }
        Arrays.clear(t);
        return r;
    }

    /**
     * Exponentiation by a SECRET exponent, a signing nonce or an ephemeral secret, as in w = g^r,
     * of a base that can change from call to call - for SM9, the pairing value each key exchange
     * forms with its peer's value and raises to its ephemeral. The exponent is split into four,
     * whose bits are read together, a column at a time from the top: each column squares the
     * running value once and multiplies in an entry of a table of sixteen, the same steps whatever
     * the bits are, and each entry is read out of the table in full, so that neither the operations
     * nor the memory they read depend on the exponent - eighty-one squarings and eighty-one
     * products, and seven more products for the table, where windows of four bits over the exponent
     * blinded into 320 bits would take 316 squarings and ninety-four products. Unlike {@link #pow},
     * it does not leak the exponent's Hamming weight or individual bits. The exponent must satisfy
     * 0 &lt;= e &lt; N (every SM9 secret exponent is reduced mod the group order N), and <b>the
     * base must lie in the order-N subgroup of G_T</b>, which every value SM9 raises to a secret
     * power does - each is an R-ate pairing result, and the final exponentiation puts it there.
     * <p>
     * The split is Galbraith and Scott's. Raising to q is a Frobenius map, a handful of products in
     * F_q, and on the order-N subgroup it is raising to LAMBDA = q mod N = 6t^2, so g^e is the
     * product of g^k0, (g^q)^k1, (g^(q^2))^k2 and (g^(q^3))^k3 for any four exponents with
     * k0 + k1 LAMBDA + k2 LAMBDA^2 + k3 LAMBDA^3 = e mod N; {@code decompose} forms four below 2^82
     * from e and a random draw. They are read in Faz-Hernandez, Longa and Sanchez's sign-aligned
     * columns: k0 is odd and its digits are 1 or -1, the top one 1, and the digits of the other
     * three are 0 or the digit of k0 in the same column - see {@code recode}. So entry v + 8s of the
     * table, for v = v1 + 2v2 + 4v3 and s = 0 or 1, is (g g^(q v1) g^(q^2 v2) g^(q^3 v3))^(1 - 2s),
     * and each column reads the entry its digits of k1, k2 and k3 pick out, with s = 1 where its
     * digit of k0 is -1: the inverse of an element of the subgroup is its conjugate, so the last
     * eight entries are the conjugates of the first eight. Every entry carries g or its inverse, so
     * none is 1, an element all but one of whose twelve coefficients are 0.
     * <p>
     * A random multiple of N added to e, as the other secret exponentiations and multiplications
     * blind their secret, would not change the four exponents - the split of e + rN is the split of
     * e - so decompose blinds the split itself, with random multiples of four vectors that stand for
     * 0 mod N: sixty-three random bits, as many as {@code SM9Curve.blind} draws for its multiple of N,
     * and the columns differ from call to call whatever e is. They take the same steps whatever e is
     * as well, from a top column whose digit of k0 is 1, so that no column spends its steps on the
     * running value 1.
     * <p>
     * The blinding leaves each running value a power of the base fixed by the columns already taken,
     * so anyone who knows the base could work out, column by column, the value each step is given.
     * So the table's entries carry a random non-zero m in F_q drawn for the call - the Frobenius
     * fixes m, so the conjugates carry it too - and the running value carries a factor f of F_q,
     * starting at m: the square {@link #cyclotomicSqr} forms of f y carries f^2, and a product with an
     * entry carries f m, so f is updated with each step and divided out once at the end. Every value
     * the exponentiation works on carries a factor no two calls share, as the Miller loop's values do.
     * <p>
     * Reading the table in full still leaves one step of each column's scan depending on the
     * column's bits: the one that moves its entry into place, the only step that moves any words. So
     * each column's scan starts at an entry drawn at random for it, one byte each of an
     * eighty-two-byte draw the call makes, and wraps round, and the value it reads into is cleared
     * first - see {@link #lookup}.
     */
    public Fp12 powSecure(BigInteger e)
    {
        if (e.signum() < 0 || e.compareTo(SM9Curve.N) >= 0)
        {
            // the javadoc's 0 <= e < N was a precondition nothing enforced: a wider exponent was
            // silently truncated to the fixed width and a negative one read as its magnitude, and
            // the split below bounds the exponents it forms only for an e in range.
            throw new IllegalArgumentException("exponent must be in the range [0, N)");
        }
        int[][] k = decompose(e);
        int[] m = new int[Fp.SIZE];
        int[] table = null;
        try
        {
            Fp.randomNonZero(CryptoServicesRegistrar.getSecureRandom(), m, 0);
            table = splitTable(m);
            return splitPower(table, m, k);
        }
        finally
        {
            // in a finally, as the draws after the split can throw, and the split stands for e
            for (int j = 0; j < k.length; ++j)
            {
                Arrays.clear(k[j]);
            }
            Arrays.clear(m);
            Arrays.clear(table);
        }
    }

    // the number of columns powSecure reads, the number of entries in its table, and the number of
    // 32-bit words each of the four exponents it splits the exponent into is formed on: k0 lies
    // below 2^SPLIT_COLUMNS and the other three below 2^(SPLIT_COLUMNS - 1) - see decompose
    private static final int SPLIT_COLUMNS = 82;
    private static final int SPLIT_ENTRIES = 16;
    private static final int SPLIT_WORDS = 3;

    // the rows b0 = (2t + 1, 0, 2t, 1), b1 = (2t, t + 1, -t, t), b2 = (t + 1, t, t, -2t) and
    // b3 = (2t + 1, -t, -t - 1, -t) of a basis of the lattice of the (x0, x1, x2, x3) with
    // x0 + x1 LAMBDA + x2 LAMBDA^2 + x3 LAMBDA^3 = 0 mod N, LAMBDA = 6t^2, each coordinate x t + y
    // given as {x, y}; the basis's determinant is -N, the lattice's index in Z^4
    private static final int[][][] SPLIT_BASIS = {
        { { 2, 1 }, { 0, 0 }, { 2, 0 }, { 0, 1 } },
        { { 2, 0 }, { 1, 1 }, { -1, 0 }, { 1, 0 } },
        { { 1, 1 }, { 1, 0 }, { 1, 0 }, { -2, 0 } },
        { { 2, 1 }, { -1, 0 }, { -1, -1 }, { -1, 0 } } };

    // -b_i mod 2^96 for each row, coordinate by coordinate, and b0 itself, as SPLIT_WORDS words each
    private static final int[][][] SPLIT_NEGATED_ROWS = new int[4][4][];
    private static final int[][] SPLIT_ROW0 = new int[4][];

    // round(2^320 a_i / N) as eight words, for a0 = 6t^3 + 6t^2 + 2t, a1 = 6t^3 - t, a2 = 2t + 1 and
    // a3 = 6t^3 + 6t^2 + t: (1, 0, 0, 0) = sum_i (a_i / N) b_i
    private static final int[][] SPLIT_ROUNDING = new int[4][];

    static
    {
        BigInteger t = SM9Curve.T, t2 = t.multiply(t), t3 = t2.multiply(t);
        BigInteger two = BigInteger.valueOf(2), six = BigInteger.valueOf(6);
        BigInteger mod = BigInteger.ONE.shiftLeft(32 * SPLIT_WORDS);
        BigInteger[] a = { six.multiply(t3.add(t2)).add(two.multiply(t)), six.multiply(t3).subtract(t),
            two.multiply(t).add(BigInteger.ONE), six.multiply(t3.add(t2)).add(t) };
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                BigInteger b = t.multiply(BigInteger.valueOf(SPLIT_BASIS[i][j][0]))
                    .add(BigInteger.valueOf(SPLIT_BASIS[i][j][1]));
                SPLIT_NEGATED_ROWS[i][j] = Nat.fromBigInteger(32 * SPLIT_WORDS, b.negate().mod(mod));
                if (i == 0)
                {
                    SPLIT_ROW0[j] = Nat.fromBigInteger(32 * SPLIT_WORDS, b);
                }
            }
            SPLIT_ROUNDING[i] = Nat.fromBigInteger(256,
                a[i].shiftLeft(320).add(SM9Curve.N.shiftRight(1)).divide(SM9Curve.N));
        }
    }

    // the multiples of the rows the blinding's multiples start from, the smallest that keep every
    // coordinate non-negative whatever the exponent and the draw are - see decompose
    private static final int[] SPLIT_OFFSETS = { 65536, 32771, -43688, -76461 };

    private static final long M = 0xFFFFFFFFL;

    /**
     * Four exponents k0, k1, k2 and k3 with k0 + k1 LAMBDA + k2 LAMBDA^2 + k3 LAMBDA^3 = e mod N,
     * for LAMBDA = q mod N, k0 odd and below 2^82 and the others non-negative and below 2^81, each
     * as three 32-bit words, least significant first - those {@link #powSecure} reads - formed from
     * e, below N, and a random draw, in the same steps whatever e and the draw are.
     * <p>
     * The rows of SPLIT_BASIS stand for 0 mod N: b_i0 + b_i1 LAMBDA + b_i2 LAMBDA^2 + b_i3 LAMBDA^3
     * = 0 mod N, and they form a basis of the lattice of all such vectors, whose entries are at most
     * 2t + 1 in magnitude. (e, 0, 0, 0) is sum_i y_i b_i for y_i = e a_i / N, a_i as for
     * SPLIT_ROUNDING, and, taking c_i as floor((e G_i + 2^319) / 2^320) for G_i = round(2^320 a_i / N),
     * within 1/2 + 2^-65 of y_i, (e, 0, 0, 0) - sum_i c_i b_i stands for e and has coordinates no
     * larger in magnitude than 1/2 + 2^-65 times the sum of the magnitudes in their column of the
     * basis: 3.5t + 2, 1.5t + 1, 2.5t + 1 and 2t + 1 (Babai's rounding).
     * <p>
     * To that, (SPLIT_OFFSETS[i] + r_i) b_i is added for each row, for sixteen bits r_i drawn for
     * the row, which leaves what the exponents stand for as it is, the rows standing for 0 mod N: the
     * offsets make every coordinate non-negative, whatever e and r are, with k0 below 2^82 and the
     * others below 2^81. The lowest bit of r_0 is not drawn but set where k0 would otherwise be even,
     * b0's first coordinate being odd: sixty-three random bits in all, and the map from the r_i to the
     * four exponents is one to one, the rows being independent. The coordinates are formed mod 2^96,
     * three words, which holds them exactly, and c_i mod 2^96 is words 10 to 12 of e G_i + 2^319.
     */
    private static int[][] decompose(BigInteger e)
    {
        byte[] draw = new byte[8];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(draw);

        int[] x = Nat.fromBigInteger(256, e), zz = new int[16], d = new int[SPLIT_WORDS];
        int[] s = new int[SPLIT_WORDS], p = new int[2 * SPLIT_WORDS];
        int[][] k = new int[4][SPLIT_WORDS];
        System.arraycopy(x, 0, k[0], 0, SPLIT_WORDS);
        for (int i = 0; i < 4; ++i)
        {
            // d = c_i - (SPLIT_OFFSETS[i] + r_i), r_0 without its lowest bit
            Nat.mul(8, x, SPLIT_ROUNDING[i], zz);
            long c = (zz[9] & M) + 0x80000000L;
            for (int w = 0; w < SPLIT_WORDS; ++w)
            {
                c = (c >>> 32) + (zz[10 + w] & M);
                d[w] = (int)c;
            }
            int r = ((draw[2 * i] & 0xFF) << 8) | (draw[2 * i + 1] & 0xFF);
            long o = SPLIT_OFFSETS[i] + (r & (i == 0 ? 0xFFFE : 0xFFFF));
            s[0] = (int)o;
            s[1] = (int)(o >> 32);
            s[2] = (int)(o >> 32);
            Nat.subFrom(SPLIT_WORDS, s, d);

            // k -= d b_i
            for (int j = 0; j < 4; ++j)
            {
                Nat.mul(SPLIT_WORDS, d, 0, SPLIT_NEGATED_ROWS[i][j], 0, p, 0);
                Nat.addTo(SPLIT_WORDS, p, k[j]);
            }
        }

        // the lowest bit of r_0: b0 again where k0 is even
        int even = (k[0][0] & 1) ^ 1;
        for (int j = 0; j < 4; ++j)
        {
            Nat.caddTo(SPLIT_WORDS, even, SPLIT_ROW0[j], k[j]);
        }

        Arrays.clear(draw);
        Arrays.clear(x);
        Arrays.clear(zz);
        Arrays.clear(d);
        Arrays.clear(s);
        Arrays.clear(p);
        return k;
    }

    /**
     * Rewrites the exponents {@link #decompose} forms, in place, as the digits of their
     * sign-aligned columns: k0 as S, whose bit c is set for each column c below the top one in which
     * the digit of k0 is -1, and each other k_j as D_j = (k_j + S) xor S, whose bit c is set where
     * the digit of k_j in column c is not 0, and so is the digit of k0.
     * <p>
     * The digit of k0 in the top column is 1, and in each column c below it 2 b_(c + 1) - 1, for bit
     * b_(c + 1) of k0: the digits add up to k0 - b_0 + 1 = k0, k0 being odd, which is P - S for P the
     * columns whose digit is 1. And for 0 &lt;= k_j &lt;= P, as every k_j below 2^81 is, P being at
     * least 2^81, k_j + S lies below 2^82, D_j agrees with it on P and with its complement on S, and
     * (D_j and P) - (D_j and S) = ((k_j + S) and P) - S + ((k_j + S) and S) = k_j.
     */
    private static void recode(int[][] k)
    {
        int[] s = k[0];
        Nat.shiftDownBit(SPLIT_WORDS, s, 0);
        for (int w = 0; w < SPLIT_WORDS; ++w)
        {
            s[w] = ~s[w];
        }
        s[SPLIT_WORDS - 1] &= (1 << (SPLIT_COLUMNS - 1 - 32 * (SPLIT_WORDS - 1))) - 1;
        for (int j = 1; j < 4; ++j)
        {
            Nat.addTo(SPLIT_WORDS, s, k[j]);
            for (int w = 0; w < SPLIT_WORDS; ++w)
            {
                k[j][w] ^= s[w];
            }
        }
    }

    // column c of the digits recode leaves: the index of the table entry the column reads, v + 8s
    private static int splitColumn(int[][] k, int c)
    {
        int w = c >>> 5, b = c & 31;
        return (((k[0][w] >>> b) & 1) << 3) | (((k[3][w] >>> b) & 1) << 2) | (((k[2][w] >>> b) & 1) << 1)
            | ((k[1][w] >>> b) & 1);
    }

    /**
     * The table {@link #powSecure} reads: entry v + 8s, for v = v1 + 2v2 + 4v3 from 0 to 7 and s = 0
     * or 1, is m (g g^(q v1) g^(q^2 v2) g^(q^3 v3))^(1 - 2s), g being this element.
     */
    private int[] splitTable(int[] m)
    {
        int[] table = new int[SPLIT_ENTRIES * SIZE], t = new int[MUL_SCRATCH];
        Fp12 q2 = SM9Pairing.frobenius2(this);
        int[][] images = { SM9Pairing.frobenius(this).limbs, q2.limbs, SM9Pairing.frobenius(q2).limbs };
        for (int i = 0; i < SIZE; i += Fp.SIZE)
        {
            Fp.mul(limbs, i, m, 0, table, i);
        }
        for (int j = 0; j < images.length; ++j)
        {
            // the entries from 2^j to 2^(j + 1) - 1 are those below 2^j times g^(q^(j + 1))
            for (int d = 0; d < 1 << j; ++d)
            {
                mul(table, d * SIZE, images[j], 0, table, ((1 << j) + d) * SIZE, t, 0);
            }
        }
        for (int d = 0; d < SPLIT_ENTRIES / 2; ++d)
        {
            // entry d + 8 is entry d raised to q^6, which fixes m: F_p2 is fixed, v^(q^6) = -v and
            // w^(q^6) = -w, as SM9Pairing.frobenius6 has it
            int z = (d + SPLIT_ENTRIES / 2) * SIZE;
            System.arraycopy(table, d * SIZE, table, z, SIZE);
            Fp2.neg(table, z + Fp2.SIZE, table, z + Fp2.SIZE);
            Fp2.neg(table, z + 2 * Fp2.SIZE, table, z + 2 * Fp2.SIZE);
            Fp2.neg(table, z + 5 * Fp2.SIZE, table, z + 5 * Fp2.SIZE);
        }
        for (int j = 0; j < images.length; ++j)
        {
            Arrays.clear(images[j]);
        }
        Arrays.clear(t);
        return table;
    }

    /**
     * g^(k0 + k1 q + k2 q^2 + k3 q^3), for g the element {@link #splitTable} made the given table from
     * with the given m and four exponents as {@link #decompose} forms them, which it rewrites, by the
     * sign-aligned columns {@link #powSecure} describes.
     */
    private static Fp12 splitPower(int[] table, int[] m, int[][] k)
    {
        recode(k);

        // the entry each column's lookup starts its scan at, a byte drawn for it
        byte[] starts = new byte[SPLIT_COLUMNS];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(starts);

        // the running value r = f y, from the top column, whose entry carries m
        int[] r = new int[SIZE], x = new int[SIZE], f = new int[Fp.SIZE], t = new int[MUL_SCRATCH];
        int top = SPLIT_COLUMNS - 1;
        lookup(table, SPLIT_ENTRIES, splitColumn(k, top), starts[top], r);
        System.arraycopy(m, 0, f, 0, Fp.SIZE);
        for (int c = top - 1; c >= 0; --c)
        {
            cyclotomicSqr(r, 0, f, 0, r, 0, t, 0);
            Fp.sqr(f, 0, f, 0);
            lookup(table, SPLIT_ENTRIES, splitColumn(k, c), starts[c], x);
            mul(r, 0, x, 0, r, 0, t, 0);
            Fp.mul(f, 0, m, 0, f, 0);
        }
        Fp.inv(f, 0, f, 0);
        for (int i = 0; i < SIZE; i += Fp.SIZE)
        {
            Fp.mul(r, i, f, 0, r, i);
        }
        Arrays.clear(starts);
        Arrays.clear(f);
        Arrays.clear(x);
        Arrays.clear(t);
        return new Fp12(r);
    }

    /**
     * Exponentiation by a SECRET exponent, as {@link #powSecure}, of a PUBLIC base that is raised to
     * one exponent after another - for SM9, the pairing value a master public key fixes, which
     * signing, encryption, encapsulation and the key exchange raise to their nonce or ephemeral: by
     * Lim and Lee's comb, over two tables of thirty-two powers of this element each that the first
     * call makes and this element keeps, 24 KB of values anyone who knows the base can compute. Each
     * call takes thirty-one squarings and sixty-three products, where {@link #powSecure}, which makes
     * its table for the call, takes eighty-one squarings and eighty-eight products, seven of them for
     * its table; the first also makes the tables, in 288 squarings and sixty-two products. The result
     * is powSecure's, and so are the preconditions: 0 &lt;= e &lt; N, and <b>the base must lie in
     * the order-N subgroup of G_T</b>.
     * <p>
     * The exponent is blinded with a random multiple of N into exactly 320 bits, as the secret
     * multiplications in G1 and G2 blind their scalars - see {@code SM9Curve.blind} - and its bits
     * fall into sixty-four columns of five, column c holding bits c, c + 64, c + 128, c + 192 and
     * c + 256.
     * Entry d of the first table, for d = d0 + 2d1 + 4d2 + 8d3 + 16d4, is this element g raised to
     * 1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256, and entry d of the second is that raised to
     * 2^32. The columns are read in pairs, c and c + 32, from the top pair down: each pair multiplies
     * into the running value the entry column c's bits pick out of the first table and the one column
     * c + 32's bits pick out of the second, the same steps whatever the bits are, and the running
     * value is squared once between one pair and the next - thirty-one times, where a comb over the
     * first table alone squares it between one column and the next, sixty-three times; and each entry
     * is read out of its table in full, through {@link #lookup}, so that neither the operations nor
     * the memory they read depend on the exponent. The 1 in each entry's exponent makes entry 0 of
     * the first table g rather than 1, an element all but one of whose twelve coefficients are 0,
     * which a column whose bits are all 0 would otherwise multiply in, and entry 0 of the second
     * g^(2^32). The product of the entries the columns read then carries g^(2^64 - 1) as well, so
     * the comb is run over the blinded exponent less 2^64 - 1, which the blinding leaves positive.
     * <p>
     * As in {@link #powSecure}, every call multiplies the tables' entries by a random non-zero m in
     * F_q, drawn for it, before it reads any of them, and the running value carries a factor f of
     * F_q that starts at m, is squared with each squaring and multiplied by m with each product,
     * and is divided out at the end: every value the exponentiation works on carries a factor no
     * two calls share. The copies of the tables the factor is applied to are erased when the call
     * ends; the tables themselves hold only powers of the base. Two threads that make the first
     * call together may both make the tables, and get equal tables.
     * <p>
     * And as in {@link #powSecure}, each column's scan of its table starts at an entry drawn at
     * random for it, one byte each of a sixty-four-byte draw the call makes, and wraps round, and the
     * value it reads into is cleared first, so that the step of the scan that moves the column's
     * entry into place does not give the column's bits away - see {@link #lookup}.
     */
    public Fp12 powSecureFixedBase(BigInteger e)
    {
        if (e.signum() < 0 || e.compareTo(SM9Curve.N) >= 0)
        {
            throw new IllegalArgumentException("exponent must be in the range [0, N)");
        }
        int[][] tables = combTables();
        int[] k = SM9Curve.blind(e);
        try
        {
            Nat.subFrom(k.length, SM9Curve.COMB_OFFSET, k);
            return combPower(tables, k);
        }
        finally
        {
            // in a finally, as combPower's draws can throw, and the blinded exponent stands for e
            Arrays.clear(k);
        }
    }

    // the number of tables powSecureFixedBase's comb reads, and the number of steps it takes: each reads
    // one column from each table, and each but the first squares the running value first
    private static final int COMB_TABLES = 2;
    private static final int COMB_STEPS = SM9Curve.COMB_SPACING / COMB_TABLES;

    /**
     * The tables {@link #powSecureFixedBase} reads: the first holds the thirty-two elements
     * g^(1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256) for d = d0 + 2d1 + 4d2 + 8d3 + 16d4 from
     * 0 to 31, g being this element, and the second the first's raised to 2^32, made on the first
     * call and kept.
     */
    private int[][] combTables()
    {
        int[][] tables = combTables;
        if (tables == null)
        {
            tables = new int[COMB_TABLES][SM9Curve.COMB_ENTRIES * SIZE];
            int[] b = Arrays.clone(limbs), t = new int[MUL_SCRATCH];
            for (int i = 0; i < SM9Curve.COMB_TEETH; ++i)
            {
                for (int j = 0; j < COMB_TABLES; ++j)
                {
                    if (i > 0 || j > 0)
                    {
                        // b = g^(2^(64 i + 32 j))
                        for (int s = 0; s < COMB_STEPS; ++s)
                        {
                            cyclotomicSqr(b, 0, null, 0, b, 0, t, 0);
                        }
                    }
                    if (i == 0)
                    {
                        // entry 0 of table j is g^(2^(32 j))
                        System.arraycopy(b, 0, tables[j], 0, SIZE);
                    }
                    // the entries of table j from 2^i to 2^(i + 1) - 1 are those below 2^i times b
                    for (int d = 0; d < 1 << i; ++d)
                    {
                        mul(tables[j], d * SIZE, b, 0, tables[j], ((1 << i) + d) * SIZE, t, 0);
                    }
                }
            }
            combTables = tables;
        }
        return tables;
    }

    /**
     * g^(k + 2^64 - 1) for the base g of the given tables and k the 320 bits of ten 32-bit words,
     * least significant first, by the comb {@link #powSecureFixedBase} describes.
     */
    private static Fp12 combPower(int[][] tables, int[] k)
    {
        int[] m = new int[Fp.SIZE];
        Fp.randomNonZero(CryptoServicesRegistrar.getSecureRandom(), m, 0);

        // the tables' entries times m, for this call
        int[][] tm = new int[tables.length][];
        for (int j = 0; j < tm.length; ++j)
        {
            tm[j] = new int[tables[j].length];
            for (int i = 0; i < tm[j].length; i += Fp.SIZE)
            {
                Fp.mul(tables[j], i, m, 0, tm[j], i);
            }
        }

        // the entry each column's lookup starts its scan at, a byte drawn for it
        byte[] starts = new byte[SM9Curve.COMB_SPACING];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(starts);

        // the running value r = f y, from the top pair of columns, whose entries carry m each: table
        // j is read over the columns from j COMB_STEPS on
        int[] r = new int[SIZE], x = new int[SIZE], f = new int[Fp.SIZE], t = new int[MUL_SCRATCH];
        int top = COMB_STEPS - 1;
        lookup(tm[0], SM9Curve.COMB_ENTRIES, SM9Curve.combColumn(k, top), starts[top], r);
        System.arraycopy(m, 0, f, 0, Fp.SIZE);
        for (int j = 1; j < tm.length; ++j)
        {
            int c = j * COMB_STEPS + top;
            lookup(tm[j], SM9Curve.COMB_ENTRIES, SM9Curve.combColumn(k, c), starts[c], x);
            mul(r, 0, x, 0, r, 0, t, 0);
            Fp.mul(f, 0, m, 0, f, 0);
        }
        for (int s = top - 1; s >= 0; --s)
        {
            cyclotomicSqr(r, 0, f, 0, r, 0, t, 0);
            Fp.sqr(f, 0, f, 0);
            for (int j = 0; j < tm.length; ++j)
            {
                int c = j * COMB_STEPS + s;
                lookup(tm[j], SM9Curve.COMB_ENTRIES, SM9Curve.combColumn(k, c), starts[c], x);
                mul(r, 0, x, 0, r, 0, t, 0);
                Fp.mul(f, 0, m, 0, f, 0);
            }
        }
        Fp.inv(f, 0, f, 0);
        for (int i = 0; i < SIZE; i += Fp.SIZE)
        {
            Fp.mul(r, i, f, 0, r, i);
        }
        Arrays.clear(m);
        Arrays.clear(starts);
        Arrays.clear(f);
        for (int j = 0; j < tm.length; ++j)
        {
            Arrays.clear(tm[j]);
        }
        Arrays.clear(x);
        Arrays.clear(t);
        return new Fp12(r);
    }

    /**
     * z = the entry at d of a table of the given number of elements, a power of 2, one after another,
     * read by moving every entry into z under a mask that is set for the entry at d alone, so that
     * which memory is read does not depend on d.
     * <p>
     * Of the steps of the scan, only the one that reaches the entry at d moves any words into z -
     * none, if z already held that entry - so the step at which words move, and whether any do,
     * would give d away to whoever can observe the moves. The scan therefore starts at the entry at
     * start, taken mod the number of entries, and wraps round, reaching the entry at d at step
     * (d - start) mod the number of entries, and z is cleared first: for a start drawn at random, the
     * step that moves words is uniform whatever d is, and it moves the whole entry, whichever entry
     * z held.
     */
    static void lookup(int[] table, int entries, int d, int start, int[] z)
    {
        Nat.zero(SIZE, z);
        for (int j = 0; j < entries; ++j)
        {
            int i = (start + j) & (entries - 1);
            Nat.cmov(SIZE, ((i ^ d) - 1) >>> 31, table, i * SIZE, z, 0);
        }
    }

    /**
     * z = x y, by Karatsuba's form in w with the reduction w^3 = v, w^4 = v w: six F_p4 products
     * where the schoolbook form takes nine, formed as {@link Fp4#mulWide} forms them, and each of the
     * twelve coefficients of the result formed from them unreduced and reduced once - twelve
     * reductions for the fifty-four products in F_q. Every wide value lies between -30q^2 and 33q^2.
     * z may be x or y.
     */
    static void mul(int[] x, int xOff, int[] y, int yOff, int[] z, int zOff, int[] t, int tOff)
    {
        int n = Fp4.SIZE, w = Fp.WIDE;
        int v0 = tOff, v1 = v0 + 4 * w, v2 = v1 + 4 * w, p1 = v2 + 4 * w, p3 = p1 + 4 * w, p2 = p3 + 4 * w;
        int sx = p2 + 4 * w, sy = sx + n, o = sy + n, tt = o + w;

        Fp4.mulWide(x, xOff, y, yOff, t, v0, t, tt);                     // x0 y0
        Fp4.mulWide(x, xOff + n, y, yOff + n, t, v1, t, tt);             // x1 y1
        Fp4.mulWide(x, xOff + 2 * n, y, yOff + 2 * n, t, v2, t, tt);     // x2 y2
        Fp4.add(x, xOff, x, xOff + n, t, sx);
        Fp4.add(y, yOff, y, yOff + n, t, sy);
        Fp4.mulWide(t, sx, t, sy, t, p1, t, tt);                         // (x0 + x1)(y0 + y1)
        Fp4.add(x, xOff + n, x, xOff + 2 * n, t, sx);
        Fp4.add(y, yOff + n, y, yOff + 2 * n, t, sy);
        Fp4.mulWide(t, sx, t, sy, t, p3, t, tt);                         // (x1 + x2)(y1 + y2)
        Fp4.add(x, xOff, x, xOff + 2 * n, t, sx);
        Fp4.add(y, yOff, y, yOff + 2 * n, t, sy);
        Fp4.mulWide(t, sx, t, sy, t, p2, t, tt);                         // (x0 + x2)(y0 + y2)

        // for e in F_p4, e v = -2 e_3 + e_2 u + (e_0 + e_1 u) v, e_0 to e_3 its coefficients of 1, u,
        // v and u v

        // x0 y0 + (x1 y2 + x2 y1) v, with x1 y2 + x2 y1 = p3 - v1 - v2
        Fp.combine(t, v0, 1, p3 + 3 * w, -2, v1 + 3 * w, 2, v2 + 3 * w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff);
        Fp.combine(t, v0 + w, 1, p3 + 2 * w, 1, v1 + 2 * w, -1, v2 + 2 * w, -1, t, o);
        Fp.reduceWide(t, o, z, zOff + Fp.SIZE);
        Fp.combine(t, v0 + 2 * w, 1, p3, 1, v1, -1, v2, -1, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * Fp.SIZE);
        Fp.combine(t, v0 + 3 * w, 1, p3 + w, 1, v1 + w, -1, v2 + w, -1, t, o);
        Fp.reduceWide(t, o, z, zOff + 3 * Fp.SIZE);

        // x0 y1 + x1 y0 + x2 y2 v, with x0 y1 + x1 y0 = p1 - v0 - v1
        Fp.combine(t, p1, 1, v0, -1, v1, -1, v2 + 3 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + n);
        Fp.combine(t, p1 + w, 1, v0 + w, -1, v1 + w, -1, v2 + 2 * w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + Fp.SIZE);
        Fp.combine(t, p1 + 2 * w, 1, v0 + 2 * w, -1, v1 + 2 * w, -1, v2, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 2 * Fp.SIZE);
        Fp.combine(t, p1 + 3 * w, 1, v0 + 3 * w, -1, v1 + 3 * w, -1, v2 + w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 3 * Fp.SIZE);

        // x0 y2 + x2 y0 + x1 y1 = p2 - v0 - v2 + v1
        for (int i = 0; i < 4; ++i)
        {
            Fp.combine(t, p2 + i * w, 1, v0 + i * w, -1, v2 + i * w, -1, v1 + i * w, 1, t, o);
            Fp.reduceWide(t, o, z, zOff + 2 * n + i * Fp.SIZE);
        }
    }

    /**
     * z = x^2, by Chung and Hasan's SQR2: (a + b w + c w^2)^2 = (a^2 + 2bc v) + (2ab + c^2 v) w
     * + (b^2 + 2ac) w^2, with b^2 + 2ac = (a - b + c)^2 - a^2 - c^2 + 2ab + 2bc: two F_p4 products and
     * three squarings, formed as {@link Fp4#mulWide} and {@link Fp4#sqrWide} form them, and each
     * coefficient of the result formed from them unreduced and reduced once. Every wide value lies
     * between -30q^2 and 33q^2. z may be x.
     */
    static void sqr(int[] x, int xOff, int[] z, int zOff, int[] t, int tOff)
    {
        int n = Fp4.SIZE, w = Fp.WIDE;
        int a2 = tOff, ab = a2 + 4 * w, s2 = ab + 4 * w, bc = s2 + 4 * w, c2 = bc + 4 * w, s = c2 + 4 * w;
        int o = s + n, tt = o + w;

        Fp4.sqrWide(x, xOff, t, a2, t, tt);                              // a^2
        Fp4.mulWide(x, xOff, x, xOff + n, t, ab, t, tt);                 // ab
        Fp4.sub(x, xOff, x, xOff + n, t, s);
        Fp4.add(t, s, x, xOff + 2 * n, t, s);
        Fp4.sqrWide(t, s, t, s2, t, tt);                                 // (a - b + c)^2
        Fp4.mulWide(x, xOff + n, x, xOff + 2 * n, t, bc, t, tt);         // bc
        Fp4.sqrWide(x, xOff + 2 * n, t, c2, t, tt);                      // c^2

        // for e in F_p4, e v = -2 e_3 + e_2 u + (e_0 + e_1 u) v

        // a^2 + 2bc v
        Fp.combine(t, a2, 1, bc + 3 * w, -4, t, o);
        Fp.reduceWide(t, o, z, zOff);
        Fp.combine(t, a2 + w, 1, bc + 2 * w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + Fp.SIZE);
        Fp.combine(t, a2 + 2 * w, 1, bc, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * Fp.SIZE);
        Fp.combine(t, a2 + 3 * w, 1, bc + w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + 3 * Fp.SIZE);

        // 2ab + c^2 v
        Fp.combine(t, ab, 2, c2 + 3 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + n);
        Fp.combine(t, ab + w, 2, c2 + 2 * w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + Fp.SIZE);
        Fp.combine(t, ab + 2 * w, 2, c2, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 2 * Fp.SIZE);
        Fp.combine(t, ab + 3 * w, 2, c2 + w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 3 * Fp.SIZE);

        // (a - b + c)^2 - a^2 - c^2 + 2ab + 2bc
        for (int i = 0; i < 4; ++i)
        {
            Fp.combine(t, s2 + i * w, 1, a2 + i * w, -1, c2 + i * w, -1, ab + i * w, 2, bc + i * w, 2, t, o);
            Fp.reduceWide(t, o, z, zOff + 2 * n + i * Fp.SIZE);
        }
    }

    /**
     * z = x^2 by Granger and Scott's formula, for x in the cyclotomic subgroup - see
     * {@link #cyclotomicSquare()} - or, when m is not null, for x = m y with y in that subgroup and
     * m a non-zero element of F_q, the form in which {@link #powSecure} carries its running values.
     * x^2 is then m^2 y^2, and the formula for y^2 gives it in the coefficients a, b and c of m y as
     * (3a^2 - 2m conj(a)) + (3c^2 v + 2m conj(b)) w + (3b^2 - 2m conj(c)) w^2, conj being F_q-linear:
     * the same three F_p4 squarings and twelve products by m. The formula without the m would not
     * give it, since m y is not in the subgroup. z may be x.
     * <p>
     * The squares are formed as {@link Fp4#sqrWide} forms them, and so are the products by m, or,
     * where m is null, the coefficients of x themselves - see {@link Fp#toWide} - and each coefficient
     * of the result is formed from them unreduced and reduced once. conj(x + y v) = x - y v adds or
     * subtracts each coefficient of its argument, and c^2 v enters by the coefficients of c^2 that
     * the product by v moves, so that no operand is the constant 0, as a negation's is. Every wide
     * value lies between -21q^2 and 27q^2.
     */
    static void cyclotomicSqr(int[] x, int xOff, int[] m, int mOff, int[] z, int zOff, int[] t, int tOff)
    {
        int n = Fp4.SIZE, w = Fp.WIDE;
        int a2 = tOff, b2 = a2 + 4 * w, c2 = b2 + 4 * w, e = c2 + 4 * w, o = e + 12 * w, tt = o + w;
        Fp4.sqrWide(x, xOff, t, a2, t, tt);
        Fp4.sqrWide(x, xOff + n, t, b2, t, tt);
        Fp4.sqrWide(x, xOff + 2 * n, t, c2, t, tt);

        // m times each of the twelve coefficients of x, or where m is null each coefficient itself
        if (m == null)
        {
            for (int i = 0; i < 12; ++i)
            {
                Fp.toWide(x, xOff + i * Fp.SIZE, t, e + i * w);
            }
        }
        else
        {
            for (int i = 0; i < 12; ++i)
            {
                Fp.mulWide(x, xOff + i * Fp.SIZE, m, mOff, t, e + i * w);
            }
        }
        int ma = e, mb = e + 4 * w, mc = e + 8 * w;

        // 3a^2 - 2m conj(a), conj(a) = a_0 + a_1 u - (a_2 + a_3 u) v
        Fp.combine(t, a2, 3, ma, -2, t, o);
        Fp.reduceWide(t, o, z, zOff);
        Fp.combine(t, a2 + w, 3, ma + w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + Fp.SIZE);
        Fp.combine(t, a2 + 2 * w, 3, ma + 2 * w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * Fp.SIZE);
        Fp.combine(t, a2 + 3 * w, 3, ma + 3 * w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + 3 * Fp.SIZE);

        // 3c^2 v + 2m conj(b), c^2 v = -2 e_3 + e_2 u + (e_0 + e_1 u) v for e = c^2
        Fp.combine(t, c2 + 3 * w, -6, mb, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + n);
        Fp.combine(t, c2 + 2 * w, 3, mb + w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + n + Fp.SIZE);
        Fp.combine(t, c2, 3, mb + 2 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 2 * Fp.SIZE);
        Fp.combine(t, c2 + w, 3, mb + 3 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 3 * Fp.SIZE);

        // 3b^2 - 2m conj(c)
        Fp.combine(t, b2, 3, mc, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * n);
        Fp.combine(t, b2 + w, 3, mc + w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * n + Fp.SIZE);
        Fp.combine(t, b2 + 2 * w, 3, mc + 2 * w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * n + 2 * Fp.SIZE);
        Fp.combine(t, b2 + 3 * w, 3, mc + 3 * w, 2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * n + 3 * Fp.SIZE);
    }

    /**
     * z = the compressed form of x^2, for x in the cyclotomic subgroup given by its compressed form c:
     * written, as Karabina writes F_p12 = F_p4[w]/(w^3 - v) over F_p4 = F_p2[v]/(v^2 - u), as
     * (g0 + g1 v) + (g2 + g3 v) w + (g4 + g5 v) w^2, x is fixed by g2, g3, g4 and g5, the last four
     * F_p2 coefficients of its limbs - see {@link #decompress} - and by Karabina's formulas
     * h2 = 2(g2 + 3u B45), h3 = 3(A45 - (u + 1) B45) - 2g3, h4 = 3(A23 - (u + 1) B23) - 2g4 and
     * h5 = 2(g5 + 3B23), for A_ij = (g_i + g_j)(g_i + u g_j) and B_ij = g_i g_j, x^2 is fixed by
     * h2, h3, h4 and h5: four F_p2 products where {@link #cyclotomicSqr} takes nine F_p2 squares.
     * The products are formed as {@link Fp2#mulWide} forms them, and so are the g_i themselves - see
     * {@link Fp#toWide} - and each coefficient of h2 to h5 is formed from them unreduced and reduced
     * once: for B in F_p2, u B = -2 B_1 + B_0 u and (u + 1) B = (B_0 - 2 B_1) + (B_0 + B_1) u. Every
     * wide value lies between -24q^2 and 27q^2. z may be c.
     */
    static void compressedSqr(int[] c, int cOff, int[] z, int zOff, int[] t, int tOff)
    {
        int n = Fp2.SIZE, w = Fp.WIDE;
        int g2 = cOff, g3 = cOff + n, g4 = cOff + 2 * n, g5 = cOff + 3 * n;
        int b45 = tOff, b23 = b45 + 2 * w, a45 = b23 + 2 * w, a23 = a45 + 2 * w, g = a23 + 2 * w, s = g + 8 * w;
        int r = s + n, o = r + n, tt = o + w;
        Fp2.mulWide(c, g4, c, g5, t, b45, t, tt);                        // B45
        Fp2.mulWide(c, g2, c, g3, t, b23, t, tt);                        // B23
        Fp2.add(c, g4, c, g5, t, s);
        Fp2.addMulU(c, g4, c, g5, t, r);
        Fp2.mulWide(t, s, t, r, t, a45, t, tt);                          // A45
        Fp2.add(c, g2, c, g3, t, s);
        Fp2.addMulU(c, g2, c, g3, t, r);
        Fp2.mulWide(t, s, t, r, t, a23, t, tt);                          // A23

        // the eight coefficients of g2 to g5, in their order in c
        for (int i = 0; i < 8; ++i)
        {
            Fp.toWide(c, cOff + i * Fp.SIZE, t, g + i * w);
        }

        // h2 = 2g2 + 6u B45
        Fp.combine(t, g, 2, b45 + w, -12, t, o);
        Fp.reduceWide(t, o, z, zOff);
        Fp.combine(t, g + w, 2, b45, 6, t, o);
        Fp.reduceWide(t, o, z, zOff + Fp.SIZE);

        // h3 = 3A45 - 3(u + 1) B45 - 2g3
        Fp.combine(t, a45, 3, b45, -3, b45 + w, 6, g + 2 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + n);
        Fp.combine(t, a45 + w, 3, b45, -3, b45 + w, -3, g + 3 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + n + Fp.SIZE);

        // h4 = 3A23 - 3(u + 1) B23 - 2g4
        Fp.combine(t, a23, 3, b23, -3, b23 + w, 6, g + 4 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * n);
        Fp.combine(t, a23 + w, 3, b23, -3, b23 + w, -3, g + 5 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * n + Fp.SIZE);

        // h5 = 2g5 + 6B23
        Fp.combine(t, g + 6 * w, 2, b23, 6, t, o);
        Fp.reduceWide(t, o, z, zOff + 3 * n);
        Fp.combine(t, g + 7 * w, 2, b23 + w, 6, t, o);
        Fp.reduceWide(t, o, z, zOff + 3 * n + Fp.SIZE);
    }

    /**
     * The elements of the cyclotomic subgroup whose compressed forms - see {@link #compressedSqr} -
     * are the first count in c, one after another. Karabina gives each element's g1 as
     * (u g5^2 + 3g4^2 - 2g3) / 4g2, or as 2g4 g5 / g3 where g2 is 0, and its g0 as
     * u(2g1^2 + g2 g5 - 3g3 g4) + 1. Both quotients are formed and one is kept under a mask, and the
     * denominators are inverted together - one inversion, and three F_p2 products for each other
     * denominator (Montgomery's trick). None is 0: where g3 is 0 as well, the denominator is taken
     * as 1, over a numerator of 0.
     * <p>
     * The squares and products in the numerators and in g0 are formed as {@link Fp2#sqrWide} and
     * {@link Fp2#mulWide} form them, and so are g3 and 1 - see {@link Fp#toWide} - and each
     * coefficient of the numerators, of 2g4 g5 and of g0 is formed from them unreduced and reduced
     * once: for B in F_p2, u B = -2 B_1 + B_0 u. Every wide value lies between -22q^2 and 12q^2.
     */
    static Fp12[] decompress(int[] c, int count)
    {
        int n = Fp2.SIZE, w = Fp.WIDE;
        int[] num = new int[count * n], den = new int[count * n], pre = new int[count * n];

        // wide values: g4^2, g5^2, g3 and g4 g5 for the numerators, then g1^2, g2 g5 and g3 g4 for g0
        // over the first three; 1; and the sum reduced
        int s4 = 0, s5 = s4 + 2 * w, g3w = s5 + 2 * w, b45 = g3w + 2 * w, one = b45 + 2 * w, o = one + w;
        int s1 = s4, b25 = s5, b34 = g3w;
        int a = o + w, tt = a + n;
        int[] t = new int[tt + Fp2.MUL_SCRATCH];
        Fp.toWide(Fp2.ONE.limbs, 0, t, one);
        for (int j = 0; j < count; ++j)
        {
            int g2 = j * COMPRESSED_SIZE, g3 = g2 + n, g4 = g2 + 2 * n, g5 = g2 + 3 * n, q = j * n;
            Fp2.sqrWide(c, g4, t, s4, t, tt);
            Fp2.sqrWide(c, g5, t, s5, t, tt);
            Fp.toWide(c, g3, t, g3w);
            Fp.toWide(c, g3 + Fp.SIZE, t, g3w + w);

            // u g5^2 + 3g4^2 - 2g3
            Fp.combine(t, s5 + w, -2, s4, 3, g3w, -2, t, o);
            Fp.reduceWide(t, o, num, q);
            Fp.combine(t, s5, 1, s4 + w, 3, g3w + w, -2, t, o);
            Fp.reduceWide(t, o, num, q + Fp.SIZE);

            Fp2.add(c, g2, c, g2, t, a);
            Fp2.add(t, a, t, a, den, q);                        // 4g2

            // 2g4 g5
            Fp2.mulWide(c, g4, c, g5, t, b45, t, tt);
            Fp.combine(t, b45, 2, t, o);
            Fp.reduceWide(t, o, t, a);
            Fp.combine(t, b45 + w, 2, t, o);
            Fp.reduceWide(t, o, t, a + Fp.SIZE);

            int g2Zero = Fp2.zeroBit(c, g2);
            Nat.cmov(n, g2Zero, t, a, num, q);
            Nat.cmov(n, g2Zero, c, g3, den, q);
            Nat.cmov(n, g2Zero & Fp2.zeroBit(c, g3), Fp2.ONE.limbs, 0, den, q);
        }

        System.arraycopy(den, 0, pre, 0, n);
        for (int j = 1; j < count; ++j)
        {
            Fp2.mul(pre, (j - 1) * n, den, j * n, pre, j * n, t, tt);
        }
        int[] inv = new int[n];
        Fp2.inv(pre, (count - 1) * n, inv, 0);
        for (int j = count - 1; j > 0; --j)
        {
            Fp2.mul(inv, 0, pre, (j - 1) * n, t, a, t, tt);     // the inverse of den_j
            Fp2.mul(inv, 0, den, j * n, inv, 0, t, tt);         // of den_0 ... den_(j-1)
            System.arraycopy(t, a, den, j * n, n);
        }
        System.arraycopy(inv, 0, den, 0, n);

        Fp12[] r = new Fp12[count];
        for (int j = 0; j < count; ++j)
        {
            int g2 = j * COMPRESSED_SIZE, g3 = g2 + n, g4 = g2 + 2 * n, g5 = g2 + 3 * n;
            int[] z = new int[SIZE];
            System.arraycopy(c, g2, z, 2 * n, COMPRESSED_SIZE);
            Fp2.mul(num, j * n, den, j * n, z, n, t, tt);       // g1
            Fp2.sqrWide(z, n, t, s1, t, tt);
            Fp2.mulWide(c, g2, c, g5, t, b25, t, tt);
            Fp2.mulWide(c, g3, c, g4, t, b34, t, tt);

            // g0 = u B + 1 = (1 - 2 B_1) + B_0 u for B = 2g1^2 + g2 g5 - 3g3 g4
            Fp.combine(t, s1 + w, -4, b25 + w, -2, b34 + w, 6, one, 1, t, o);
            Fp.reduceWide(t, o, z, 0);
            Fp.combine(t, s1, 2, b25, 1, b34, -3, t, o);
            Fp.reduceWide(t, o, z, Fp.SIZE);
            r[j] = new Fp12(z);
        }
        Arrays.clear(num);
        Arrays.clear(den);
        Arrays.clear(pre);
        Arrays.clear(inv);
        Arrays.clear(t);
        return r;
    }

    /**
     * z = x (l0 + l2 w^2) for l0 in F_p4 and l2 in F_p2, the shape of the Miller loop's line
     * values, which have neither a w term nor a v w^2 term:
     * (a + b w + c w^2)(l0 + l2 w^2) = (a l0 + b l2 v) + (b l0 + c l2 v) w + (c l0 + a l2) w^2, with
     * c l0 + a l2 = (a + c)(l0 + l2) - a l0 - c l2. It takes five F_p4 products - a l0, b l0, c l2,
     * b l2 and (a + c)(l0 + l2) - of which the two by l2 cost two F_p2 products each rather than
     * three: thirteen F_p2 products in all, where {@link #mul} takes eighteen. They are formed as
     * {@link Fp4#mulWide} and {@link Fp4#mulFp2Wide} form them, and each coefficient of the result
     * is formed from them unreduced and reduced once. Every wide value lies between -10q^2 and
     * 11q^2. z may be x.
     */
    static void mulSparse(int[] x, int xOff, int[] l0, int l0Off, int[] l2, int l2Off, int[] z, int zOff,
        int[] t, int tOff)
    {
        int n = Fp4.SIZE, w = Fp.WIDE;
        int al0 = tOff, bl0 = al0 + 4 * w, cl2 = bl0 + 4 * w, bl2 = cl2 + 4 * w, p = bl2 + 4 * w, s = p + 4 * w;
        int l = s + n, o = l + n, tt = o + w;

        Fp4.mulWide(x, xOff, l0, l0Off, t, al0, t, tt);                  // a l0
        Fp4.mulWide(x, xOff + n, l0, l0Off, t, bl0, t, tt);              // b l0
        Fp4.mulFp2Wide(x, xOff + 2 * n, l2, l2Off, t, cl2, t, tt);       // c l2
        Fp4.mulFp2Wide(x, xOff + n, l2, l2Off, t, bl2, t, tt);           // b l2
        Fp4.add(x, xOff, x, xOff + 2 * n, t, s);                         // a + c
        Fp2.add(l0, l0Off, l2, l2Off, t, l);                             // l0 + l2
        System.arraycopy(l0, l0Off + Fp2.SIZE, t, l + Fp2.SIZE, Fp2.SIZE);
        Fp4.mulWide(t, s, t, l, t, p, t, tt);                            // (a + c)(l0 + l2)

        // for e in F_p4, e v = -2 e_3 + e_2 u + (e_0 + e_1 u) v

        // a l0 + b l2 v
        Fp.combine(t, al0, 1, bl2 + 3 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff);
        Fp.combine(t, al0 + w, 1, bl2 + 2 * w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + Fp.SIZE);
        Fp.combine(t, al0 + 2 * w, 1, bl2, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + 2 * Fp.SIZE);
        Fp.combine(t, al0 + 3 * w, 1, bl2 + w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + 3 * Fp.SIZE);

        // b l0 + c l2 v
        Fp.combine(t, bl0, 1, cl2 + 3 * w, -2, t, o);
        Fp.reduceWide(t, o, z, zOff + n);
        Fp.combine(t, bl0 + w, 1, cl2 + 2 * w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + Fp.SIZE);
        Fp.combine(t, bl0 + 2 * w, 1, cl2, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 2 * Fp.SIZE);
        Fp.combine(t, bl0 + 3 * w, 1, cl2 + w, 1, t, o);
        Fp.reduceWide(t, o, z, zOff + n + 3 * Fp.SIZE);

        // (a + c)(l0 + l2) - a l0 - c l2
        for (int i = 0; i < 4; ++i)
        {
            Fp.combine(t, p + i * w, 1, al0 + i * w, -1, cl2 + i * w, -1, t, o);
            Fp.reduceWide(t, o, z, zOff + 2 * n + i * Fp.SIZE);
        }
    }

    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof Fp12))
        {
            return false;
        }
        return Fp2.isEqual(limbs, ((Fp12)other).limbs);
    }

    public int hashCode()
    {
        return Arrays.hashCode(limbs);
    }
}
