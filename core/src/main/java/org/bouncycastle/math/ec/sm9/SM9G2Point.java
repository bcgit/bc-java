package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;

/**
 * Affine point of the group G2 for SM9, the order-N subgroup of the sextic twist
 * E'(F_p2): y^2 = x^3 + 5u (GM/T 0044.5-2016). Immutable. G1 by contrast is an ordinary
 * prime-field curve, handled by the custom constant-time
 * {@link org.bouncycastle.math.ec.custom.gm.SM9P256V1Curve} (see {@link SM9Curve#G1}).
 */
public class SM9G2Point
{
    static final SM9G2Point INFINITY = new SM9G2Point();

    final Fp2 x;
    final Fp2 y;
    final boolean infinity;

    // the coefficients of the lines of this point's Miller loop, one line after another, which
    // SM9Pairing.multiPair - for public points only - computes on first use and keeps here
    volatile int[] millerLines;

    // the table multiply reads for P2, which P2 alone makes, on its first call, and keeps here - see
    // combTable()
    private volatile int[] combTable;

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
     * Scalar multiplication, returning [k]this. This point must be in G2, as every point decode()
     * returns is.
     * <p>
     * The KGC runs it on its secrets - [ks]P2 for a signature master key and [t2]P2 for each
     * encryption user key it derives - so four things are done for it:
     * <ul>
     * <li>The scalar is blinded with a random multiple of N, which leaves [k]this unchanged for a
     * point of G2, into a value of exactly 320 bits, the first of them set (see
     * {@link SM9Curve#blind}): the multiplication runs the same steps from the same leading bit
     * whatever k is, where a ladder over k itself stayed at the point at infinity, on cheaper
     * arithmetic, through k's leading zero bits.</li>
     * <li>It works in Jacobian coordinates, (X, Y, Z) standing for (X/Z^2, Y/Z^3), on values that
     * carry a random factor drawn for the call, as the Miller loop starts from a random
     * representative of its G2 argument: every value it works on carries a factor no two calls
     * share.</li>
     * <li>It inverts once, at the end, where the affine arithmetic inverted at every addition
     * and doubling.</li>
     * <li>It does not branch on the scalar's bits, nor choose by them the memory it reads, and its
     * additions take the cases their formulas do not, an operand at infinity among them, by the
     * same steps as any other. The F_p2 arithmetic underneath runs in constant time.</li>
     * </ul>
     * <p>
     * P2 itself, the instance {@link SM9Curve#P2} - the base of both - runs Lim and Lee's comb,
     * over a table of thirty-two multiples of P2 and their doubles that its first call makes and P2
     * keeps, 8 KB of points anyone can compute. The blinded scalar's bits fall into sixty-four
     * columns of five, column c holding bits c, c + 64, c + 128, c + 192 and c + 256, and entry d of
     * the table, for
     * d = d0 + 2d1 + 4d2 + 8d3 + 16d4, is [1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256]P2. From
     * the top column down, each column doubles the running point and adds the entry its bits pick
     * out, read out of the table in full, through {@link #lookup}. The 1 in each entry's multiple
     * makes entry 0 P2 rather than the point at infinity, which has no affine coordinates to hold;
     * the entries the columns add then carry [2^64 - 1]P2 as well, so the comb is run over the
     * blinded scalar less 2^64 - 1, which the blinding leaves positive. A call takes sixty-three
     * doublings and sixty-three additions, where the ladder takes 320 doublings and 319 additions;
     * the first also makes the table.
     * <p>
     * The entries are fixed points, whose coordinates would tell apart each column's entry as it is
     * read and added. So each call draws a random non-zero lambda of F_p2 and carries the entries
     * from (x, y) to (lambda^2 x, lambda^3 y), points of the twist y^2 = x^3 + lambda^6 5u, which that
     * map takes this one to, and runs the comb there: the doubling and the addition do not involve
     * the curve's constant, and a result (X, Y, Z) there is (X, Y, lambda Z) here. The copy of the
     * table the factor is applied to is erased when the call ends; the table itself holds only
     * multiples of P2. Each column's scan of the table starts at an entry drawn at random for it, one
     * byte each of a sixty-four-byte draw the call makes, and wraps round, and the value it reads
     * into is cleared first, so that the step of the scan that moves the column's entry into place
     * does not give the column's bits away - see {@link #lookup}. And the running point may be at
     * infinity, equal to the entry it adds, or its negation - for a small k such as 1 or 2 the
     * blinding makes one of the first two happen in about one call in thirty-two - so the table holds
     * each entry's double beside it, and the addition takes the double or the entry in place of the
     * sum under masks (see {@link #addEntry}), with no doubling but the column's.
     * <p>
     * Any other point runs a Montgomery ladder, maintaining the invariant r1 = r0 + this: one
     * addition and one doubling per bit, from (x Z^2, y Z^3, Z) for a random non-zero Z drawn for
     * the call, its two running points exchanged at each bit, or not, by a masked swap that reads
     * and writes both either way, and updated in the same steps whichever it did.
     */
    public SM9G2Point multiply(BigInteger k)
    {
        if (k.signum() < 0 || k.bitLength() > SM9Curve.N.bitLength())
        {
            // the ladder walks a fixed window of N.bitLength() bits, so a wider scalar was
            // silently truncated to its low bits and a negative one read as its magnitude -
            // each giving [k]P for a k the caller did not ask for. Every in-tree call site
            // passes a value already reduced mod N; this is for the exported method.
            throw new IllegalArgumentException("scalar must be non-negative and at most " +
                SM9Curve.N.bitLength() + " bits");
        }
        if (infinity || k.signum() == 0)
        {
            return INFINITY;
        }
        SM9G2Point r;
        if (this == SM9Curve.P2)
        {
            // the one point that keeps a table: one made from any other would be a precomputation
            // from what may be a private key, kept with it
            int[] table = combTable();
            int[] blinded = SM9Curve.blind(k);
            Nat.subFrom(blinded.length, SM9Curve.COMB_OFFSET, blinded);
            r = comb(table, blinded);
            Arrays.clear(blinded);
        }
        else
        {
            int[] blinded = SM9Curve.blind(k);
            r = ladder(blinded, SM9Curve.BLINDED_BITS);
            Arrays.clear(blinded);
        }
        return r;
    }

    // the offsets of a Jacobian point's coordinates X, Y and Z, elements of F_p2, in its limbs, the
    // size of a point, the size of an affine point x || y, the scratch space the additions and
    // doubling take, and the offset in it at which the formulas for a Jacobian point plus an affine
    // one leave the sum
    private static final int X = 0, Y = Fp2.SIZE, Z = 2 * Fp2.SIZE, POINT = 3 * Fp2.SIZE;
    private static final int AFFINE = 2 * Fp2.SIZE;
    private static final int SCRATCH = 7 * Fp.WIDE + 13 * Fp2.SIZE + Fp2.MUL_SCRATCH;
    private static final int SUM = 6 * Fp.WIDE + 7 * Fp2.SIZE;

    // the size of an entry of the comb's table: a point and its double, each x || y in affine
    // coordinates
    private static final int ENTRY = 2 * AFFINE;

    /**
     * The table {@link #multiply} reads for P2: the thirty-two points
     * [1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256]P for d = d0 + 2d1 + 4d2 + 8d3 + 16d4 from
     * 0 to 31, P being this point, each followed by its double - that of entry 0, [2]P, being entry
     * 1 - both as x || y in affine coordinates, made on the first call and kept. They are public, and
     * are made without a draw: {@link #publicAffine} brings each to affine coordinates without the
     * random factor that blinds the inversion of a point that may be secret. Two threads that make
     * the first call together may both make the table, and get equal tables.
     */
    private int[] combTable()
    {
        int[] table = combTable;
        if (table == null)
        {
            table = new int[SM9Curve.COMB_ENTRIES * ENTRY];
            int[] b = new int[POINT], s = new int[POINT], d = new int[POINT], t = new int[SCRATCH];
            System.arraycopy(x.limbs, 0, table, X, Fp2.SIZE);
            System.arraycopy(y.limbs, 0, table, Y, Fp2.SIZE);
            System.arraycopy(table, 0, b, X, AFFINE);
            System.arraycopy(Fp2.ONE.limbs, 0, b, Z, Fp2.SIZE);
            for (int i = 0; i < SM9Curve.COMB_TEETH; ++i)
            {
                if (i > 0)
                {
                    // b = [2^(64 i)]P
                    for (int j = 0; j < SM9Curve.COMB_SPACING; ++j)
                    {
                        twice(b, b, t);
                    }
                }
                // the entries from 2^i to 2^(i + 1) - 1 are those below 2^i plus b, each followed by
                // its double
                for (int e = 0; e < 1 << i; ++e)
                {
                    addAffine(b, table, e * ENTRY, s, d, t);
                    publicAffine(s, table, ((1 << i) + e) * ENTRY, t);
                    twice(s, s, t);
                    publicAffine(s, table, ((1 << i) + e) * ENTRY + AFFINE, t);
                }
            }
            // entry 0's double, [2]P, is entry 1
            System.arraycopy(table, ENTRY, table, AFFINE, AFFINE);
            combTable = table;
        }
        return table;
    }

    /**
     * [k + 2^64 - 1]P for P the point of the given table and k the 320 bits of ten 32-bit words,
     * least significant first, by the comb {@link #multiply} describes.
     */
    private static SM9G2Point comb(int[] table, int[] k)
    {
        int[] t = new int[SCRATCH];

        // the table's points (x, y), the entries and their doubles, carried to (lambda^2 x,
        // lambda^3 y), for the lambda drawn here
        int[] l = Fp2.randomNonZero().limbs, l2 = new int[Fp2.SIZE], l3 = new int[Fp2.SIZE];
        Fp2.sqr(l, 0, l2, 0, t, 0);
        Fp2.mul(l2, 0, l, 0, l3, 0, t, 0);
        int[] tl = new int[table.length];
        for (int i = 0; i < tl.length; i += AFFINE)
        {
            Fp2.mul(table, i + X, l2, 0, tl, i + X, t, 0);
            Fp2.mul(table, i + Y, l3, 0, tl, i + Y, t, 0);
        }

        // the entry each column's lookup starts its scan at, a byte drawn for it
        byte[] starts = new byte[SM9Curve.COMB_SPACING];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(starts);

        // the running point r, from the top column's entry; e holds each entry read, with its double
        int[] r = new int[POINT], e = new int[ENTRY];
        lookup(tl, SM9Curve.COMB_ENTRIES, SM9Curve.combColumn(k, SM9Curve.COMB_SPACING - 1),
            starts[SM9Curve.COMB_SPACING - 1], e);
        System.arraycopy(e, 0, r, X, AFFINE);
        System.arraycopy(Fp2.ONE.limbs, 0, r, Z, Fp2.SIZE);
        for (int c = SM9Curve.COMB_SPACING - 2; c >= 0; --c)
        {
            twice(r, r, t);
            lookup(tl, SM9Curve.COMB_ENTRIES, SM9Curve.combColumn(k, c), starts[c], e);
            addEntry(r, e, r, t);
        }

        // (X, Y, Z) on the twist the entries were carried to is (X, Y, lambda Z) on this one
        Fp2.mul(r, Z, l, 0, r, Z, t, 0);
        SM9G2Point p = affine(r);
        Arrays.clear(l);
        Arrays.clear(l2);
        Arrays.clear(l3);
        Arrays.clear(starts);
        Arrays.clear(tl);
        Arrays.clear(r);
        Arrays.clear(e);
        Arrays.clear(t);
        return p;
    }

    /**
     * z = the entry at d of a table of the given number of entries, a power of 2, each a point and
     * its double, x || y in affine coordinates, one after another, as the comb's table holds them,
     * read by moving every entry into z under a mask that is set for the entry at d alone, so that
     * which memory is read does not depend on d: the masked move BouncyCastle's lookup tables of EC
     * points make, and {@link Fp12#lookup} makes through Nat.cmov. As there, the scan starts at the
     * entry at start, taken mod the number of entries, and wraps round, and z is cleared first: for
     * a start drawn at random, the one step that moves words into z is uniform whatever d is, and it
     * moves the whole entry.
     */
    static void lookup(int[] table, int entries, int d, int start, int[] z)
    {
        Nat.zero(ENTRY, z);
        for (int s = 0; s < entries; ++s)
        {
            int i = (start + s) & (entries - 1), pos = i * ENTRY;
            int mask = ((i ^ d) - 1) >> 31;
            for (int j = 0; j < ENTRY; ++j)
            {
                z[j] ^= (z[j] ^ table[pos + j]) & mask;
            }
        }
    }

    /**
     * [k]this for a k of exactly the given number of bits, given as 32-bit words, least significant
     * first, by the Montgomery ladder over Jacobian coordinates that {@link #multiply} describes.
     */
    private SM9G2Point ladder(int[] k, int bits)
    {
        int[] r0 = new int[POINT], r1 = new int[POINT], t = new int[SCRATCH];
        ladder(k, bits, r0, r1, t);
        SM9G2Point q = affine(r0);
        Arrays.clear(r0);
        Arrays.clear(r1);
        Arrays.clear(t);
        return q;
    }

    /**
     * [k]this into r0 and [k + 1]this into r1, in Jacobian coordinates, for a k of exactly the given
     * number of bits, by that ladder, which starts from a random representative of this point and
     * keeps r1 = r0 + this throughout; t is scratch of SCRATCH limbs.
     */
    private void ladder(int[] k, int bits, int[] r0, int[] r1, int[] t)
    {
        representative(r0);
        twice(r0, r1, t);
        int swap = 0;
        for (int i = bits - 2; i >= 0; --i)
        {
            // bit 0: (r0, r1) <- (2 r0, r0 + r1); bit 1: the same with r0 and r1 exchanged. The
            // exchange is a masked swap, which reads and writes both points either way, carried
            // into the next step's: they are exchanged when a bit differs from the one before it
            int bit = (k[i >>> 5] >>> (i & 31)) & 1;
            swap ^= bit;
            Fp.cswap(swap, r0, r1);
            swap = bit;
            add(r0, r1, r1, t);
            twice(r0, r0, t);
        }
        Fp.cswap(swap, r0, r1);
    }

    // a random representative of this point in Jacobian coordinates, (x z^2, y z^3, z) for a non-zero
    // z of F_p2 drawn for the call, into p: the ladder and isInSubgroup's chain start from it
    private void representative(int[] p)
    {
        Fp2 z = Fp2.randomNonZero();
        Fp2 zz = z.square();
        System.arraycopy(x.multiply(zz).limbs, 0, p, X, Fp2.SIZE);
        System.arraycopy(y.multiply(zz.multiply(z)).limbs, 0, p, Y, Fp2.SIZE);
        System.arraycopy(z.limbs, 0, p, Z, Fp2.SIZE);
    }

    // the point the Jacobian point p stands for, as the multiplications return it: its Z is
    // inverted through Fp2.inv, which blinds the inversion with a random factor, the point being a
    // private key when the KGC derives one
    private static SM9G2Point affine(int[] p)
    {
        Fp2 z3 = new Fp2(Arrays.copyOfRange(p, Z, POINT));
        if (z3.isZero())
        {
            return INFINITY;
        }
        Fp2 zi = z3.invert();
        Fp2 zi2 = zi.square();
        return new SM9G2Point(new Fp2(Arrays.copyOfRange(p, X, Y)).multiply(zi2),
            new Fp2(Arrays.copyOfRange(p, Y, Z)).multiply(zi2.multiply(zi)));
    }

    // the affine coordinates x || y of the Jacobian point p, not at infinity, into z from zOff, for
    // a PUBLIC p - an entry of P2's table: its Z is inverted as Fp2.inv inverts, (a - b u) /
    // (a^2 + 2b^2), without the random factor that blinds the norm of what may be a secret, so that
    // making the table takes no draw
    private static void publicAffine(int[] p, int[] z, int zOff, int[] t)
    {
        int norm = 0, zi = Fp2.SIZE, zi2 = 2 * Fp2.SIZE, tt = 3 * Fp2.SIZE;
        Fp.sqr(p, Z, t, norm);
        Fp.sqr(p, Z + Fp.SIZE, t, zi);
        Fp.add(t, norm, t, zi, t, norm);
        Fp.add(t, norm, t, zi, t, norm);                        // a^2 + 2b^2
        Fp.inv(t, norm, t, norm);
        Fp2.conj(p, Z, t, zi);
        Fp2.mulFp(t, zi, t, norm, t, zi);                       // Z^-1
        Fp2.sqr(t, zi, t, zi2, t, tt);
        Fp2.mul(p, X, t, zi2, z, zOff, t, tt);                  // x = X / Z^2
        Fp2.mul(t, zi2, t, zi, t, zi2, t, tt);
        Fp2.mul(p, Y, t, zi2, z, zOff + Fp2.SIZE, t, tt);       // y = Y / Z^3
    }

    /**
     * z = 2p for p = (X, Y, Z) in Jacobian coordinates on y^2 = x^3 + 5u (the curve's a being 0) -
     * or on any y^2 = x^3 + b, which the formulas do not involve: Z3 = 2YZ,
     * so the point at infinity (Z = 0) doubles to itself and a point of order 2 (Y = 0) to infinity
     * with no case of its own. z may be p.
     * <p>
     * X^2, Y^4, (X + Y^2)^2, (3X^2)^2 and 3X^2 (4XY^2 - X3) are formed in full, as
     * {@link Fp2#sqrWide} and {@link Fp2#mulWide} form them, and each coefficient of 4XY^2, 3X^2, X3
     * and Y3 is formed from them unreduced and reduced once: twelve reductions where reducing each
     * square and product took fourteen, and six additions and subtractions in F_q where it took
     * twenty-eight. Every wide value lies between -22q^2 and 18q^2.
     */
    private static void twice(int[] p, int[] z, int[] t)
    {
        int n = Fp2.SIZE, w = Fp.WIDE, k = Fp.SIZE;
        int a = 0, c = a + 2 * w, s = c + 2 * w, d = s + 2 * w;
        int b = d + 2 * w, xb = b + n, dd = xb + n, e = dd + n, y2 = e + n, dx = y2 + n, o = dx + n, tt = o + w;
        Fp2.sqrWide(p, X, t, a, t, tt);                         // X^2
        Fp2.sqr(p, Y, t, b, t, tt);                             // Y^2
        Fp2.sqrWide(t, b, t, c, t, tt);                         // Y^4
        Fp2.add(p, X, t, b, t, xb);
        Fp2.sqrWide(t, xb, t, s, t, tt);                        // (X + Y^2)^2
        for (int i = 0; i < 2; ++i)
        {
            Fp.combine(t, s + i * w, 2, a + i * w, -2, c + i * w, -2, t, d + i * w);     // 4XY^2
            Fp.combine(t, a + i * w, 3, t, o);
            Fp.reduceWide(t, o, t, e + i * k);                  // 3X^2
        }
        Fp.reduceWide(t, d, t, dd);
        Fp.reduceWide(t, d + w, t, dd + k);
        Fp2.add(p, Y, p, Y, t, y2);
        Fp2.mul(t, y2, p, Z, z, Z, t, tt);                      // Z3 = 2YZ
        Fp2.sqrWide(t, e, t, s, t, tt);                         // (3X^2)^2
        for (int i = 0; i < 2; ++i)
        {
            Fp.combine(t, s + i * w, 1, d + i * w, -2, t, o);
            Fp.reduceWide(t, o, z, X + i * k);                  // X3 = (3X^2)^2 - 8XY^2
        }
        Fp2.sub(t, dd, z, X, t, dx);
        Fp2.mulWide(t, e, t, dx, t, a, t, tt);                  // 3X^2 (4XY^2 - X3)
        for (int i = 0; i < 2; ++i)
        {
            Fp.combine(t, a + i * w, 1, c + i * w, -8, t, o);
            Fp.reduceWide(t, o, z, Y + i * k);                  // Y3 = 3X^2 (4XY^2 - X3) - 8Y^4
        }
    }

    /**
     * z = p + r in Jacobian coordinates for two points whose difference is not infinity: the
     * ladder's two running points, which differ by the point being multiplied, and the two points of
     * each addition of isInSubgroup's chain, a running [s]P and [d]P, d being the digit, 1 or -1,
     * which differ by [s - d]P. P is not infinity there, and its order divides N h2, the order of
     * the twist, which every point of this class lies on - decode() checks it, and the arithmetic
     * keeps it - while each of the chain's eleven s - d is prime to N h2. So the two are never
     * equal, and when their x-coordinates agree they are opposite: then H = 0, and so
     * Z3 = Z1 Z2 H = 0, the point at infinity, their sum. Either may be infinity itself: the
     * ladder's, for a point of G2, when a prefix of the blinded scalar is a multiple of N - k + r*N
     * has one for a small k, [1]P passing through infinity whenever r is even - and the chain's
     * running point for a point of order 13, for which the chain meets two opposite operands as
     * well. The formulas would carry that Z = 0 into every later sum, so the result would be
     * infinity where it is not: their sum is replaced by whichever point is finite, under masks
     * taken from the two Z coordinates, in the same steps whether either is at infinity or not. z
     * may be p or r. For operands that may be equal, {@link #addAny} takes that case as well.
     * <p>
     * X3 and Y3 are formed from s^2, H^3, X1 Z2^2 H^2 and the two products Y3 takes, formed in full,
     * as {@link Fp2#sqrWide} and {@link Fp2#mulWide} form them, unreduced, and each of their
     * coefficients is reduced once: thirty reductions where reducing each square and product took
     * thirty-two, and six additions and subtractions in F_q where it took fourteen. Every wide value
     * lies between -5q^2 and 8q^2.
     */
    private static void add(int[] p, int[] r, int[] z, int[] t)
    {
        int n = Fp2.SIZE, w = Fp.WIDE, k = Fp.SIZE;
        int h3 = 0, uh2 = h3 + 2 * w, s2 = uh2 + 2 * w;
        int z1z1 = s2 + 2 * w, z2z2 = z1z1 + n, u1 = z2z2 + n, s1 = u1 + n, h = s1 + n, s = h + n, hh = s + n;
        int hhh = hh + n, v = hhh + n, dx = v + n, sum = dx + n, o = sum + POINT, tt = o + w;
        Fp2.sqr(p, Z, t, z1z1, t, tt);
        Fp2.sqr(r, Z, t, z2z2, t, tt);
        Fp2.mul(p, X, t, z2z2, t, u1, t, tt);                   // X1 Z2^2
        Fp2.mul(p, Y, r, Z, t, s1, t, tt);
        Fp2.mul(t, s1, t, z2z2, t, s1, t, tt);                  // Y1 Z2^3
        Fp2.mul(r, X, t, z1z1, t, h, t, tt);
        Fp2.sub(t, h, t, u1, t, h);                             // H = X2 Z1^2 - X1 Z2^2
        Fp2.mul(r, Y, p, Z, t, s, t, tt);
        Fp2.mul(t, s, t, z1z1, t, s, t, tt);
        Fp2.sub(t, s, t, s1, t, s);                             // Y2 Z1^3 - Y1 Z2^3
        Fp2.sqr(t, h, t, hh, t, tt);
        Fp2.mulWide(t, h, t, hh, t, h3, t, tt);                 // H^3
        Fp.reduceWide(t, h3, t, hhh);
        Fp.reduceWide(t, h3 + w, t, hhh + k);
        Fp2.mulWide(t, u1, t, hh, t, uh2, t, tt);               // X1 Z2^2 H^2
        Fp.reduceWide(t, uh2, t, v);
        Fp.reduceWide(t, uh2 + w, t, v + k);
        Fp2.sqrWide(t, s, t, s2, t, tt);
        for (int i = 0; i < 2; ++i)
        {
            Fp.combine(t, s2 + i * w, 1, h3 + i * w, -1, uh2 + i * w, -2, t, o);
            Fp.reduceWide(t, o, t, sum + X + i * k);            // X3 = s^2 - H^3 - 2 X1 Z2^2 H^2
        }
        Fp2.sub(t, v, t, sum + X, t, dx);
        Fp2.mulWide(t, s, t, dx, t, s2, t, tt);
        Fp2.mulWide(t, s1, t, hhh, t, h3, t, tt);
        for (int i = 0; i < 2; ++i)
        {
            Fp.combine(t, s2 + i * w, 1, h3 + i * w, -1, t, o);
            Fp.reduceWide(t, o, t, sum + Y + i * k);            // Y3 = s (X1 Z2^2 H^2 - X3) - Y1 Z2^3 H^3
        }
        Fp2.mul(p, Z, r, Z, t, sum + Z, t, tt);
        Fp2.mul(t, sum + Z, t, h, t, sum + Z, t, tt);           // Z3 = Z1 Z2 H

        int pAtInfinity = atInfinity(p), rAtInfinity = atInfinity(r);
        Nat.cmov(POINT, rAtInfinity, p, 0, t, sum);
        Nat.cmov(POINT, pAtInfinity, r, 0, t, sum);
        System.arraycopy(t, sum, z, 0, POINT);
    }

    /**
     * z = p + a for p = (X1, Y1, Z1) in Jacobian coordinates and a = (x2, y2) in affine ones, from
     * aOff: {@link #add} with Z2 = 1, on y^2 = x^3 + b for any b, which neither formula involves.
     * The comb's table is made by it, and the point it is made from, unlike the ladder's running
     * point, is equal to the point it adds, entry 0, to make entry 1. The formulas give (0, 0, 0) for
     * the sum 2p of two equal points, and for p at infinity a point that is not the sum, a, where for
     * p the negation of a they give the point at infinity, which is the sum, H being 0 and so
     * Z3 = Z1 H = 0. So it forms 2p into d each time, and takes it, or a with Z = 1, in place of the
     * sum under masks taken from H and the difference of the y-coordinates and from Z1, in the same
     * steps whether either case arises or not; the comb's additions take the double from the table
     * instead (see {@link #addEntry}). z may be p; d may be neither.
     */
    private static void addAffine(int[] p, int[] a, int aOff, int[] z, int[] d, int[] t)
    {
        twice(p, d, t);
        int equal = sum(p, a, aOff, t), pAtInfinity = atInfinity(p);
        Nat.cmov(POINT, equal, d, 0, t, SUM);
        Nat.cmov(AFFINE, pAtInfinity, a, aOff, t, SUM);
        Nat.cmov(Fp2.SIZE, pAtInfinity, Fp2.ONE.limbs, 0, t, SUM + Z);
        System.arraycopy(t, SUM, z, 0, POINT);
    }

    /**
     * z = p + a for p = (X1, Y1, Z1) in Jacobian coordinates and an entry of the comb's table, e, the
     * point a = (x2, y2) followed by its double 2a, both in affine coordinates: as {@link #addAffine}
     * adds, but with the double of a, where the running point is equal to a, read from the entry
     * rather than formed from the running point beside the sum. The comb's running point may be at
     * infinity, equal to a or its negation, and the addition takes 2a, or a, with Z = 1 in place of
     * the sum under the same masks, in the same steps whether either case arises or not. z may be p.
     */
    private static void addEntry(int[] p, int[] e, int[] z, int[] t)
    {
        int equal = sum(p, e, 0, t), pAtInfinity = atInfinity(p);
        Nat.cmov(AFFINE, equal, e, AFFINE, t, SUM);
        Nat.cmov(AFFINE, pAtInfinity, e, 0, t, SUM);
        Nat.cmov(Fp2.SIZE, equal | pAtInfinity, Fp2.ONE.limbs, 0, t, SUM + Z);
        System.arraycopy(t, SUM, z, 0, POINT);
    }

    // the sum (X3, Y3, Z3) of p = (X1, Y1, Z1) in Jacobian coordinates and a = (x2, y2) in affine
    // ones, from aOff, by the formulas, into t from SUM; returns 1 if H and the difference of the
    // y-coordinates are both 0, as they are when p and a are the same point, and 0 if not. X3 and
    // Y3 are formed as add forms them: twenty reductions where reducing each square and product took
    // twenty-two, and six additions and subtractions in F_q where it took fourteen
    private static int sum(int[] p, int[] a, int aOff, int[] t)
    {
        int n = Fp2.SIZE, w = Fp.WIDE, k = Fp.SIZE;
        int h3 = 0, xh2 = h3 + 2 * w, s2 = xh2 + 2 * w;
        int z1z1 = s2 + 2 * w, h = z1z1 + n, s = h + n, hh = s + n, hhh = hh + n, v = hhh + n, dx = v + n;
        int o = SUM + POINT, tt = o + w;
        Fp2.sqr(p, Z, t, z1z1, t, tt);
        Fp2.mul(a, aOff + X, t, z1z1, t, h, t, tt);
        Fp2.sub(t, h, p, X, t, h);                              // H = x2 Z1^2 - X1
        Fp2.mul(a, aOff + Y, p, Z, t, s, t, tt);
        Fp2.mul(t, s, t, z1z1, t, s, t, tt);
        Fp2.sub(t, s, p, Y, t, s);                              // y2 Z1^3 - Y1
        Fp2.sqr(t, h, t, hh, t, tt);
        Fp2.mulWide(t, h, t, hh, t, h3, t, tt);                 // H^3
        Fp.reduceWide(t, h3, t, hhh);
        Fp.reduceWide(t, h3 + w, t, hhh + k);
        Fp2.mulWide(p, X, t, hh, t, xh2, t, tt);                // X1 H^2
        Fp.reduceWide(t, xh2, t, v);
        Fp.reduceWide(t, xh2 + w, t, v + k);
        Fp2.sqrWide(t, s, t, s2, t, tt);
        for (int i = 0; i < 2; ++i)
        {
            Fp.combine(t, s2 + i * w, 1, h3 + i * w, -1, xh2 + i * w, -2, t, o);
            Fp.reduceWide(t, o, t, SUM + X + i * k);            // X3 = s^2 - H^3 - 2 X1 H^2
        }
        Fp2.sub(t, v, t, SUM + X, t, dx);
        Fp2.mulWide(t, s, t, dx, t, s2, t, tt);
        Fp2.mulWide(p, Y, t, hhh, t, h3, t, tt);
        for (int i = 0; i < 2; ++i)
        {
            Fp.combine(t, s2 + i * w, 1, h3 + i * w, -1, t, o);
            Fp.reduceWide(t, o, t, SUM + Y + i * k);            // Y3 = s (X1 H^2 - X3) - Y1 H^3
        }
        Fp2.mul(p, Z, t, h, t, SUM + Z, t, tt);                 // Z3 = Z1 H
        return Fp2.zeroBit(t, h) & Fp2.zeroBit(t, s);
    }

    // 1 if p's Z coordinate is 0 - p is the point at infinity - and 0 if not, all its limbs read
    private static int atInfinity(int[] p)
    {
        int d = 0;
        for (int i = Z; i < POINT; ++i)
        {
            d |= p[i];
        }
        return 1 + ((d | -d) >> 31);
    }

    /**
     * z = p + r for any two points in Jacobian coordinates: {@link #add}, which takes an operand at
     * infinity and two opposite operands, and, for two equal ones, which it would take to (0, 0, 0),
     * the double of p, formed into d each time and taken under a mask. isInSubgroup() adds
     * pi([t]P) and pi^2([t]P) to [t + 1]P by it, though those additions meet none of these cases
     * for any point of the twist other than infinity (see {@link #isInSubgroup()}): it takes them
     * there all the same, at the cost of a doubling each, so that the test does not rest on that
     * argument alone. z may be p or r; d may be neither.
     */
    private static void addAny(int[] p, int[] r, int[] z, int[] d, int[] t)
    {
        int same = samePoint(p, r, t);
        twice(p, d, t);
        add(p, r, z, t);
        Nat.cmov(POINT, same, d, 0, z, 0);
    }

    // 1 if the Jacobian points p and r are the same point - both at infinity, or neither and
    // X1 Z2^2 = X2 Z1^2 and Y1 Z2^3 = Y2 Z1^3 - and 0 if not, in the same steps whichever
    private static int samePoint(int[] p, int[] r, int[] t)
    {
        int z1 = 0, z2 = Fp2.SIZE, a = 2 * Fp2.SIZE, b = 3 * Fp2.SIZE, tt = 4 * Fp2.SIZE;
        Fp2.sqr(p, Z, t, z1, t, tt);
        Fp2.sqr(r, Z, t, z2, t, tt);
        Fp2.mul(p, X, t, z2, t, a, t, tt);
        Fp2.mul(r, X, t, z1, t, b, t, tt);
        Fp2.sub(t, a, t, b, t, a);
        int sameX = Fp2.zeroBit(t, a);                          // X1 Z2^2 = X2 Z1^2
        Fp2.mul(t, z1, p, Z, t, z1, t, tt);
        Fp2.mul(t, z2, r, Z, t, z2, t, tt);
        Fp2.mul(p, Y, t, z2, t, a, t, tt);
        Fp2.mul(r, Y, t, z1, t, b, t, tt);
        Fp2.sub(t, a, t, b, t, a);
        int sameY = Fp2.zeroBit(t, a);                          // Y1 Z2^3 = Y2 Z1^3
        int pAtInfinity = atInfinity(p), rAtInfinity = atInfinity(r);
        int finite = (pAtInfinity | rAtInfinity) ^ 1;
        return (sameX & sameY & finite) | (pAtInfinity & rAtInfinity);
    }

    // z = pi(p) for p in Jacobian coordinates, pi being the Frobenius isInSubgroup() tests by: it
    // takes (x, y) to (x^q gamma^-2, y^q gamma^-3), and so (X, Y, Z) to (X^q gamma^-2, Y^q gamma^-3,
    // Z^q), the q-th power of an element of F_p2 being its conjugate, and gamma^-2 and gamma^-3
    // elements of F_q. z may be p.
    private static void frobenius(int[] p, int[] z)
    {
        Fp2.conj(p, X, z, X);
        Fp2.mulFp(z, X, SM9Pairing.FROB1_X.limbs, 0, z, X);
        Fp2.conj(p, Y, z, Y);
        Fp2.mulFp(z, Y, SM9Pairing.FROB1_Y.limbs, 0, z, Y);
        Fp2.conj(p, Z, z, Z);
    }

    /**
     * Uncompressed encoding 0x04 || x || y, each F_p2 coordinate written high
     * dimension first (u-coefficient then constant), 32 bytes per F_p component;
     * 129 bytes total.
     */
    public byte[] getEncoded()
    {
        if (infinity)
        {
            // there is no 129-byte form of it, and decode() takes only that form - emitting the
            // standard's one-octet 0x00 here would give the class an encoding it cannot read
            // back, the emit/parse asymmetry this implementation avoids elsewhere. Previously a
            // NullPointerException off the absent coordinates.
            throw new IllegalStateException("SM9 G2 point at infinity has no uncompressed encoding");
        }
        byte[] out = new byte[129];
        out[0] = 0x04;
        fp2Bytes(x, out, 1);
        fp2Bytes(y, out, 65);
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
        if (!p.isInSubgroup())
        {
            throw new IllegalArgumentException("SM9 G2 point not in the order-N subgroup");
        }
        return p;
    }

    /**
     * [t]this into u and [t + 1]this into a, in Jacobian coordinates, for the BN parameter t: from a
     * random representative p of this point, a doubling for each digit of t's non-adjacent form
     * below its top one, each followed, where the digit is 1 or -1, by an addition of p or of -p,
     * and then an addition of p. t is public, so the steps are the same whatever the point. The
     * additions are {@link #add}'s, which takes an operand at infinity and two opposite operands,
     * as a point outside G2 may give them, but not two equal ones, which no point of this class
     * gives them (see add); t is scratch of SCRATCH limbs.
     */
    private void multiplyByT(int[] u, int[] a, int[] t)
    {
        byte[] naf = SM9Pairing.T_NAF;
        int[] p = new int[POINT], m = new int[POINT];
        representative(p);
        System.arraycopy(p, 0, m, 0, POINT);
        Fp2.neg(p, Y, m, Y);                                    // -p
        System.arraycopy(p, 0, u, 0, POINT);
        for (int i = naf.length - 2; i >= 0; --i)
        {
            twice(u, u, t);
            if (naf[i] != 0)
            {
                add(u, naf[i] > 0 ? p : m, u, t);
            }
        }
        add(u, p, a, t);
        Arrays.clear(p);
        Arrays.clear(m);
    }

    /**
     * Whether this point lies in G2, the order-N subgroup of the twist curve -
     * that is, whether [N]P is the point at infinity.
     * <p>
     * Being on the twist curve is not enough. E'(F_p2) has order N*h2 with
     * h2 = 2q - N, a 256-bit composite (13 divides it), so unlike G1 - whose
     * cofactor is 1, which is what lets on-curve-and-not-infinity settle membership
     * there - the twist carries points of other orders, and the pairing has no
     * bilinear meaning on them: e(P1, A + B) does not equal e(P1, A) * e(P1, B) for
     * an A outside G2, and the Miller loop can reach a degenerate division and raise
     * ArithmeticException. Every encoded G2 point that arrives from outside the
     * process is therefore checked here, and a caller that builds one through
     * {@link #add} or {@link #multiply} can check it the same way.
     * <p>
     * The test is [t + 1]P + pi([t]P) + pi^2([t]P) = pi^3([2t]P), for the BN parameter t and
     * pi(x, y) = (x^q gamma^-2, y^q gamma^-3), the q-power Frobenius carried to the twist and back,
     * which gives the pairing its point Q1 (see {@link SM9Pairing}): whether f(pi)P = O for
     * f(x) = (t + 1) + t x + t x^2 - 2t x^3. pi takes each point of G2 to its q-th multiple, and
     * q = N + 6t^2, so on G2 f(pi) is [f(6t^2)], and N divides f(6t^2): every point of G2 passes. And
     * pi satisfies pi^2 - tr pi + q = 0 on the whole twist, tr = 6t^2 + 1 being the trace of the
     * Frobenius of E, so f(pi) is a0 + a1 pi there, a0 + a1 x being the remainder of f on division
     * by x^2 - tr x + q, and a point that passes has, applying a0 + a1 (tr - pi) as well,
     * [a0^2 + a0 a1 tr + a1^2 q]P = O. That multiplier is a multiple of N prime to h2, so the point's
     * order divides N; N does not divide h2, so the points of E'(F_p2) whose order divides N are
     * those of G2.
     * <p>
     * [t]P is formed by a chain of doublings and additions over the non-adjacent form of t, whose
     * sixty-four digits have eleven that are not 0: sixty-three doublings and ten additions, where
     * the ladder {@link #multiply} runs would take sixty-three doublings and sixty-two additions over
     * the 63 bits of t (and [N]P a ladder over 256 bits). t being public, a ladder's regularity gains
     * nothing here. [t + 1]P is one addition more. None of the chain's additions meets two equal
     * operands (see {@link #add}), so none forms the double that {@link #addAny} forms each time to
     * take that case; the rest is two additions through addAny, a doubling and three applications
     * of pi, and the two sides are compared in Jacobian coordinates, so nothing is inverted. For no
     * point of the twist other than infinity do those two additions meet an operand at infinity or
     * two equal or opposite operands, or the comparison a side at infinity: each would need [t]P,
     * [t + 1]P, [2t]P, or (t + 1) -+ t pi or (t + 1) + t pi -+ t pi^2 applied to P, to be O, and
     * the point's order, which divides N h2, h2 = 2q - N, the order of the twist being N h2, would
     * then divide the multiplier's norm, a0^2 + a0 a1 tr + a1^2 q for its remainder a0 + a1 pi,
     * each of which is prime to N h2. The additions take them through addAny all the same. The
     * cost, under a sixth of a pairing, is paid when a key is decoded, not per operation.
     */
    public boolean isInSubgroup()
    {
        if (infinity)
        {
            return true;
        }
        // not multiply(t): blinding t with a multiple of N would put the question with t + r*N in
        // place of t, and for a P of order 13 the answer to that is yes for one draw of r in
        // thirteen. The chain takes t itself, and still starts from a random representative of P,
        // which may be a secret key. The chain's additions take an operand at infinity and two
        // opposite ones, which a point of small order meets; the additions after it and the
        // comparison meet none of these cases, nor two equal operands, for any point of the twist
        // but infinity, as the javadoc says, and the additions go through addAny all the same.
        int[] a = new int[POINT], u = new int[POINT], d = new int[POINT], t = new int[SCRATCH];
        multiplyByT(u, a, t);                                   // u = [t]P, a = [t + 1]P
        frobenius(u, u);
        addAny(a, u, a, d, t);                                  // + pi([t]P)
        frobenius(u, u);
        addAny(a, u, a, d, t);                                  // + pi^2([t]P)
        frobenius(u, u);
        twice(u, u, t);                                         // pi^3([2t]P) = [2]pi^3([t]P)
        int in = samePoint(a, u, t);
        Arrays.clear(a);
        Arrays.clear(u);
        Arrays.clear(d);
        Arrays.clear(t);
        return in != 0;
    }

    // an F_p2 coordinate as 64 bytes from off, high dimension (u-coefficient) first; the point can
    // be a private key, which Fp.encode takes out of Montgomery form in constant time
    private static void fp2Bytes(Fp2 e, byte[] out, int off)
    {
        Fp.encode(e.limbs, Fp.SIZE, out, off);
        Fp.encode(e.limbs, 0, out, off + 32);
    }

    private static Fp2 fp2FromBytes(byte[] enc, int off)
    {
        int[] z = new int[Fp2.SIZE];
        if (!(Fp.decode(enc, off, z, Fp.SIZE) & Fp.decode(enc, off + 32, z, 0)))
        {
            // a coordinate at or above q would otherwise decode to the point its residue names and
            // re-encode as that point's own bytes - giving every G2 key further encodings that
            // decode to it, the malleability already closed for signatures and ciphertexts. The G1
            // decoder has always refused an out-of-range coordinate; this is its G2 counterpart.
            throw new IllegalArgumentException("SM9 G2 point coordinate is not reduced modulo q");
        }
        return new Fp2(z);
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
