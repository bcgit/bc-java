package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.PreCompCallback;
import org.bouncycastle.math.ec.PreCompInfo;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;

/**
 * The multiplications of a point of G1 by a <b>secret</b> scalar that {@link SM9Curve#multiplySecure}
 * and {@link SM9Curve#sumOfTwoMultipliesSecure} run: Lim and Lee's comb, for a point multiplied by
 * many - P1, which the KGC multiplies by its secrets, a signing key ds, which each signature multiplies
 * by its l, and an encryption master public key P_pub-e, which encryption, encapsulation and the key
 * exchange multiply by their ephemeral r, beside P1 by r h1, for the [r]Q = [r h1]P1 + [r]P_pub-e they
 * send - over a table of thirty-two multiples of the point and their doubles that the point keeps once
 * it is made, and run over two such tables at once for a sum of two multiples. It computes in F_q as
 * {@link Fp} holds it, in Jacobian coordinates, (X, Y, Z) standing for (X/Z^2, Y/Z^3), and:
 * <ul>
 * <li>blinds the scalar with a random multiple of N, which leaves [k]P unchanged for a point of G1,
 * into a value of exactly 320 bits, the first of them set (see {@link SM9Curve#blind}), so that the
 * digits it reads are not the scalar's own and differ from call to call;</li>
 * <li>carries the entries it reads by a random non-zero lambda of F_q drawn for the call, from (x, y)
 * to (lambda^2 x, lambda^3 y), points of the curve y^2 = x^3 + 5 lambda^6, which that map takes G1's
 * curve to, and runs there - the doubling and the addition do not involve the curve's constant, and
 * a result (X, Y, Z) there is (X, Y, lambda Z) here - so that the coordinates of the entry a digit
 * picks, which the arithmetic takes as operands, differ from call to call;</li>
 * <li>reads each entry by moving every entry of the table into place under a mask set for the one
 * picked alone, starting from an entry drawn at random for the read and wrapping round, into a value
 * cleared first (see {@link #lookup}), so that neither the memory read nor the step of the scan that
 * moves the entry gives the digit away;</li>
 * <li>takes the cases its addition's formulas do not - the running point at infinity, or equal to
 * the entry it adds - by the same steps as any other, wherever they can arise: it reads the entry's
 * double, which the table holds beside the entry, and the right one of the three is kept under masks
 * (see {@link #addEntry});</li>
 * <li>and brings the result to affine coordinates by one inversion, blinded by a random factor as
 * ECPoint.normalize() blinds one.</li>
 * </ul>
 * It neither branches on the scalar's bits nor reads memory they choose. BouncyCastle's multipliers,
 * which it replaces, read the scalar's own digits, from entries that were the same for every call.
 */
final class SM9G1Multiplier
{
    // the offsets of a Jacobian point's coordinates X, Y and Z, elements of F_q, in its limbs, the size
    // of a point, the size of an affine point x || y, the scratch space the arithmetic takes, and the
    // offset in it at which the addition's formulas leave the sum
    private static final int X = 0, Y = Fp.SIZE, Z = 2 * Fp.SIZE, POINT = 3 * Fp.SIZE;
    private static final int AFFINE = 2 * Fp.SIZE;
    private static final int SCRATCH = 5 * Fp.WIDE + 6 * Fp.SIZE;
    private static final int SUM = 2 * Fp.WIDE + 7 * Fp.SIZE;

    // the size of an entry of the comb's table: a point and its double, each x || y in affine
    // coordinates
    private static final int ENTRY = 2 * AFFINE;

    /**
     * The name the comb's table is kept under with its point.
     */
    static final String PRECOMP_NAME = "bc_sm9_g1_comb";

    /**
     * [k]p for a point of G1 multiplied by many, by the comb: the blinded scalar's bits fall into
     * sixty-four columns of five, column c holding bits c, c + 64, c + 128, c + 192 and c + 256, and
     * entry d of the table, for d = d0 + 2d1 + 4d2 + 8d3 + 16d4, is
     * [1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256]p. From the top column down, each column
     * doubles the running point and adds the entry its bits pick out. The 1 in each entry's multiple
     * makes entry 0 p rather than the point at infinity, which has no affine coordinates to hold;
     * the entries the columns add then carry [2^64 - 1]p as well, so the comb is run over the blinded
     * scalar less 2^64 - 1, which the blinding leaves positive. The multiple the running point stands
     * for exceeds N from the first column, since the top one takes bit 319, so any of its additions
     * may meet the point at infinity, or the entry it adds - for a small k such as 1 or 2 the
     * blinding makes one of them happen in about one call in thirty-two - and each is made by
     * {@link #addEntry}, which takes both: the table holds each entry's double beside it, which the
     * addition takes where the running point is equal to the entry, as it takes the entry itself
     * where the running point is at infinity. A call takes sixty-three doublings and sixty-three
     * additions, and no other doubling, and the first call for a point also makes its table (see
     * {@link #combTable}).
     */
    static ECPoint comb(ECPoint p, BigInteger k)
    {
        ECCurve curve = p.getCurve();
        if (p.isInfinity() || k.signum() == 0)
        {
            return curve.getInfinity();
        }
        int[] table = combTable(p);
        int[] blinded = SM9Curve.blind(k);
        Nat.subFrom(blinded.length, SM9Curve.COMB_OFFSET, blinded);
        ECPoint r = comb(curve, table, blinded);
        Arrays.clear(blinded);
        return r;
    }

    /**
     * [a]p + [b]q for two points of G1 each multiplied by many, by the comb
     * {@link #comb(ECPoint, BigInteger)} describes, run over both their tables at once: each column
     * doubles the running point once and adds the entry its bits pick out of p's table, over a's
     * blinded value, and then the one they pick out of q's, over b's, so that the two multiplications
     * share their sixty-three doublings and the inversion that brings the result to affine
     * coordinates, where two combs would each take their own and the sum of their results a third
     * inversion. Each scalar is blinded by its own multiple of N, and each table's entries are read
     * by scans of their own, each from an entry drawn for it; both tables are carried by the one
     * lambda drawn for the call, the curve it carries them to being the one their sum is formed on.
     * Every addition is made by {@link #addEntry}, which takes the running point at infinity, or
     * equal to the entry it adds, whichever table the entry is read from - as for the comb, either
     * can happen at any column, and after a column's first addition as well as its second. A call
     * takes sixty-three doublings and 127 additions, and the first call for a point also makes its
     * table. A point at infinity, or a scalar of 0, leaves the comb over the other point alone.
     */
    static ECPoint comb(ECPoint p, BigInteger a, ECPoint q, BigInteger b)
    {
        if (p.isInfinity() || a.signum() == 0)
        {
            return comb(q, b);
        }
        if (q.isInfinity() || b.signum() == 0)
        {
            return comb(p, a);
        }
        int[] tableP = combTable(p), tableQ = combTable(q);
        int[] blindedA = SM9Curve.blind(a), blindedB = SM9Curve.blind(b);
        Nat.subFrom(blindedA.length, SM9Curve.COMB_OFFSET, blindedA);
        Nat.subFrom(blindedB.length, SM9Curve.COMB_OFFSET, blindedB);
        ECPoint r = comb(p.getCurve(), new int[][]{ tableP, tableQ }, new int[][]{ blindedA, blindedB });
        Arrays.clear(blindedA);
        Arrays.clear(blindedB);
        return r;
    }

    /**
     * The table {@link #comb} reads for p: the thirty-two points
     * [1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256]p for d = d0 + 2d1 + 4d2 + 8d3 + 16d4 from 0
     * to 31, each followed by its double, both as x || y in affine coordinates, 4 KB, made on the first
     * call for p and kept with it, under {@link #PRECOMP_NAME}, as BouncyCastle's comb keeps its own.
     * p may be a private key, whose multiples the table then holds: the doublings and additions that
     * make them run from a random representative of p, (x z^2, y z^3, z) for a z drawn for the
     * purpose, rather than from p's own coordinates, each entry's double is formed from the entry as
     * it is made - that of entry 0, [2]p, being entry 1 - and they are brought to affine coordinates by
     * one inversion for each of the table's five sets of entries, of a product that carries z.
     */
    private static int[] combTable(final ECPoint p)
    {
        CombTable kept = (CombTable)p.getCurve().precompute(p, PRECOMP_NAME, new PreCompCallback()
        {
            public PreCompInfo precompute(PreCompInfo existing)
            {
                if (existing instanceof CombTable)
                {
                    return existing;
                }
                return new CombTable(makeCombTable(p));
            }
        });
        return kept.table;
    }

    private static int[] makeCombTable(ECPoint p)
    {
        int[] table = new int[SM9Curve.COMB_ENTRIES * ENTRY];
        int[] b = new int[POINT], s = new int[SM9Curve.COMB_ENTRIES * POINT], u = new int[POINT];
        int[] d = new int[POINT], t = new int[SCRATCH];
        affineCoordinates(p, table, 0);
        randomRepresentative(table, 0, b, t);
        for (int i = 0; i < SM9Curve.COMB_TEETH; ++i)
        {
            if (i > 0)
            {
                // b = [2^(64 i)]p
                for (int j = 0; j < SM9Curve.COMB_SPACING; ++j)
                {
                    twice(b, b, t);
                }
            }
            // the entries from 2^i to 2^(i + 1) - 1 are those below 2^i plus b - the first of them,
            // entry 1, the sum of p and itself - each followed by its double, as the table holds them
            for (int e = 0; e < 1 << i; ++e)
            {
                addAffine(b, table, e * ENTRY, u, d, t);
                System.arraycopy(u, 0, s, 2 * e * POINT, POINT);
                twice(u, u, t);
                System.arraycopy(u, 0, s, (2 * e + 1) * POINT, POINT);
            }
            normalize(s, 2 << i, table, (1 << i) * ENTRY, t);
        }
        // entry 0's double, [2]p, is entry 1
        System.arraycopy(table, ENTRY, table, AFFINE, AFFINE);
        Arrays.clear(b);
        Arrays.clear(s);
        Arrays.clear(u);
        Arrays.clear(d);
        Arrays.clear(t);
        return table;
    }

    // the table the comb reads for a point, kept with the point
    private static final class CombTable
        implements PreCompInfo
    {
        final int[] table;

        CombTable(int[] table)
        {
            this.table = table;
        }
    }

    /**
     * [k + 2^64 - 1]p for p the point of the given table, and k the 320 bits of ten 32-bit words,
     * least significant first, by the comb {@link #comb(ECPoint, BigInteger)} describes, as a point
     * of the given curve.
     */
    private static ECPoint comb(ECCurve curve, int[] table, int[] k)
    {
        return comb(curve, new int[][]{ table }, new int[][]{ k });
    }

    /**
     * The sum of [k_j + 2^64 - 1]p_j over the points p_j of the given tables, and k_j the 320 bits of
     * ten 32-bit words each, least significant first, by the comb {@link #comb(ECPoint, BigInteger)}
     * describes run over every table at once - each column doubling the running point once and adding
     * the entry its bits pick out of each table in turn - as a point of the given curve. Over one
     * table it is that comb.
     */
    private static ECPoint comb(ECCurve curve, int[][] tables, int[][] ks)
    {
        int[] t = new int[SCRATCH];

        // the tables' points (x, y), the entries and their doubles, carried to (lambda^2 x, lambda^3 y),
        // for the lambda drawn here
        int[] l = new int[Fp.SIZE], l2 = new int[Fp.SIZE], l3 = new int[Fp.SIZE];
        Fp.randomNonZero(CryptoServicesRegistrar.getSecureRandom(), l, 0);
        Fp.sqr(l, 0, l2, 0);
        Fp.mul(l2, 0, l, 0, l3, 0);
        int[][] tl = new int[tables.length][];
        for (int j = 0; j < tables.length; ++j)
        {
            tl[j] = new int[tables[j].length];
            for (int i = 0; i < tl[j].length; i += AFFINE)
            {
                Fp.mul(tables[j], i + X, l2, 0, tl[j], i + X);
                Fp.mul(tables[j], i + Y, l3, 0, tl[j], i + Y);
            }
        }

        // the entry each column's lookup in each table starts its scan at, a byte drawn for it: those
        // of table j from j COMB_SPACING on
        byte[] starts = new byte[tables.length * SM9Curve.COMB_SPACING];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(starts);

        // the running point r, from the top column's entry of the first table, to which those of the
        // others are added; e holds each entry read, with its double
        int[] r = new int[POINT], e = new int[ENTRY];
        int top = SM9Curve.COMB_SPACING - 1;
        lookup(tl[0], SM9Curve.COMB_ENTRIES, ENTRY, SM9Curve.combColumn(ks[0], top), starts[top], e);
        System.arraycopy(e, 0, r, X, AFFINE);
        System.arraycopy(Fp.ONE, 0, r, Z, Fp.SIZE);
        for (int j = 1; j < tables.length; ++j)
        {
            lookup(tl[j], SM9Curve.COMB_ENTRIES, ENTRY, SM9Curve.combColumn(ks[j], top),
                starts[j * SM9Curve.COMB_SPACING + top], e);
            addEntry(r, e, r, t);
        }
        for (int c = top - 1; c >= 0; --c)
        {
            twice(r, r, t);
            for (int j = 0; j < tables.length; ++j)
            {
                lookup(tl[j], SM9Curve.COMB_ENTRIES, ENTRY, SM9Curve.combColumn(ks[j], c),
                    starts[j * SM9Curve.COMB_SPACING + c], e);
                addEntry(r, e, r, t);
            }
        }

        // (X, Y, Z) on the curve the entries were carried to is (X, Y, lambda Z) on this one
        Fp.mul(r, Z, l, 0, r, Z);
        ECPoint p = toPoint(curve, r, t);
        Arrays.clear(l);
        Arrays.clear(l2);
        Arrays.clear(l3);
        for (int j = 0; j < tl.length; ++j)
        {
            Arrays.clear(tl[j]);
        }
        Arrays.clear(starts);
        Arrays.clear(r);
        Arrays.clear(e);
        Arrays.clear(t);
        return p;
    }

    /**
     * z = the entry at d of a table of the given number of entries, a power of 2, of the given number
     * of words each, one after another - for the comb, a point and its double - read by moving every
     * entry into z under a mask that is set for the entry at d alone, so that which memory is read
     * does not depend on d, as
     * {@link SM9G2Point#lookup} reads the entries of its table. As there, the scan starts at the entry
     * at start, taken mod the number of entries, and wraps round, and z is cleared first: for a start
     * drawn at random, the one step that moves words into z is uniform whatever d is, and it moves the
     * whole entry.
     */
    static void lookup(int[] table, int entries, int size, int d, int start, int[] z)
    {
        Nat.zero(size, z);
        for (int s = 0; s < entries; ++s)
        {
            int i = (start + s) & (entries - 1), pos = i * size;
            int mask = ((i ^ d) - 1) >> 31;
            for (int j = 0; j < size; ++j)
            {
                z[j] ^= (z[j] ^ table[pos + j]) & mask;
            }
        }
    }

    /**
     * z = 2p for p = (X, Y, Z) in Jacobian coordinates on y^2 = x^3 + b for any b, which the formulas
     * do not involve, the curve's a being 0: Z3 = 2YZ, so the point at infinity (Z = 0) doubles to
     * itself with no case of its own; G1 has no point of order 2. z may be p.
     * <p>
     * X^2, Y^4, (X + Y^2)^2, (3X^2)^2 and 3X^2 (4XY^2 - X3) are formed in full, as {@link Fp#sqrWide}
     * and {@link Fp#mulWide} form them, and 4XY^2, 3X^2, X3 and Y3 are formed from them unreduced and
     * reduced once: six reductions where reducing each square and product took seven, and three
     * additions and subtractions where it took fourteen. Every wide value lies between -8q^2 and 9q^2.
     */
    private static void twice(int[] p, int[] z, int[] t)
    {
        int w = Fp.WIDE, n = Fp.SIZE;
        int a = 0, c = a + w, s = c + w, d = s + w;
        int b = d + w, xb = b + n, dd = xb + n, e = dd + n, y2 = e + n, dx = y2 + n, o = dx + n;
        Fp.sqrWide(p, X, t, a);                                 // X^2
        Fp.sqr(p, Y, t, b);                                     // Y^2
        Fp.sqrWide(t, b, t, c);                                 // Y^4
        Fp.add(p, X, t, b, t, xb);
        Fp.sqrWide(t, xb, t, s);                                // (X + Y^2)^2
        Fp.combine(t, s, 2, a, -2, c, -2, t, d);                // 4XY^2
        Fp.reduceWide(t, d, t, dd);
        Fp.combine(t, a, 3, t, o);
        Fp.reduceWide(t, o, t, e);                              // 3X^2
        Fp.add(p, Y, p, Y, t, y2);
        Fp.mul(t, y2, p, Z, z, Z);                              // Z3 = 2YZ
        Fp.sqrWide(t, e, t, s);                                 // (3X^2)^2
        Fp.combine(t, s, 1, d, -2, t, o);
        Fp.reduceWide(t, o, z, X);                              // X3 = (3X^2)^2 - 8XY^2
        Fp.sub(t, dd, z, X, t, dx);
        Fp.mulWide(t, e, t, dx, t, a);                          // 3X^2 (4XY^2 - X3)
        Fp.combine(t, a, 1, c, -8, t, o);
        Fp.reduceWide(t, o, z, Y);                              // Y3 = 3X^2 (4XY^2 - X3) - 8Y^4
    }

    /**
     * z = p + a for p = (X1, Y1, Z1) in Jacobian coordinates and a = (x2, y2) in affine ones, from
     * aOff, on y^2 = x^3 + b for any b, which neither formula involves: the additions that make the
     * comb's table, whose point may be a private key, and whose first adds that point to entry 0, the
     * point itself, to make entry 1. The formulas give (0, 0, 0) for the sum 2p of two equal points,
     * and for p at infinity a point that is not the sum, a, where for p the negation of a they give
     * the point at infinity, which is the sum, H being 0 and so Z3 = Z1 H = 0. So it forms 2p into d
     * each time, and takes it, or a with Z = 1, in place of the sum under masks taken from H and the
     * difference of the y-coordinates and from Z1, in the same steps whether either case arises or
     * not, as SM9G2Point's addition for the table of its comb does; the comb's additions take the
     * double from the table instead (see {@link #addEntry}). z may be p; d may be neither.
     */
    private static void addAffine(int[] p, int[] a, int aOff, int[] z, int[] d, int[] t)
    {
        twice(p, d, t);
        int equal = sum(p, a, aOff, t), pAtInfinity = zeroBit(p, Z);
        Nat.cmov(POINT, equal, d, 0, t, SUM);
        Nat.cmov(AFFINE, pAtInfinity, a, aOff, t, SUM);
        Nat.cmov(Fp.SIZE, pAtInfinity, Fp.ONE, 0, t, SUM + Z);
        System.arraycopy(t, SUM, z, 0, POINT);
    }

    /**
     * z = p + a for p = (X1, Y1, Z1) in Jacobian coordinates and an entry of the comb's table, e, the
     * point a = (x2, y2) followed by its double 2a, both in affine coordinates: as {@link #addAffine}
     * adds, but with the double of a, where the running point is equal to a, read from the entry
     * rather than formed from the running point beside the sum. It takes 2a, or a, with Z = 1 in
     * place of the sum under the same masks, in the same steps whether either case arises or not, as
     * SM9G2Point's addition for its comb does. z may be p.
     */
    private static void addEntry(int[] p, int[] e, int[] z, int[] t)
    {
        int equal = sum(p, e, 0, t), pAtInfinity = zeroBit(p, Z);
        Nat.cmov(AFFINE, equal, e, AFFINE, t, SUM);
        Nat.cmov(AFFINE, pAtInfinity, e, 0, t, SUM);
        Nat.cmov(Fp.SIZE, equal | pAtInfinity, Fp.ONE, 0, t, SUM + Z);
        System.arraycopy(t, SUM, z, 0, POINT);
    }

    // the sum (X3, Y3, Z3) of p = (X1, Y1, Z1) in Jacobian coordinates and a = (x2, y2) in affine ones,
    // from aOff, by the formulas, into t from SUM; returns 1 if H and the difference of the
    // y-coordinates are both 0, as they are when p and a are the same point, and 0 if not. Y3 is
    // formed from its two products formed in full, unreduced, and reduced once, where each product was
    // reduced and their difference taken; every wide value lies between -q^2 and q^2
    private static int sum(int[] p, int[] a, int aOff, int[] t)
    {
        int w = Fp.WIDE, n = Fp.SIZE;
        int sv = 0, yh = sv + w;
        int z1z1 = yh + w, h = z1z1 + n, s = h + n, hh = s + n, hhh = hh + n, v = hhh + n, dx = v + n;
        int o = SUM + POINT;
        Fp.sqr(p, Z, t, z1z1);
        Fp.mul(a, aOff + X, t, z1z1, t, h);
        Fp.sub(t, h, p, X, t, h);                               // H = x2 Z1^2 - X1
        Fp.mul(a, aOff + Y, p, Z, t, s);
        Fp.mul(t, s, t, z1z1, t, s);
        Fp.sub(t, s, p, Y, t, s);                               // y2 Z1^3 - Y1
        Fp.sqr(t, h, t, hh);
        Fp.mul(t, h, t, hh, t, hhh);
        Fp.mul(p, X, t, hh, t, v);
        Fp.sqr(t, s, t, SUM + X);
        Fp.sub(t, SUM + X, t, hhh, t, SUM + X);
        Fp.sub(t, SUM + X, t, v, t, SUM + X);
        Fp.sub(t, SUM + X, t, v, t, SUM + X);                   // X3 = s^2 - H^3 - 2 X1 H^2
        Fp.sub(t, v, t, SUM + X, t, dx);
        Fp.mulWide(t, s, t, dx, t, sv);
        Fp.mulWide(p, Y, t, hhh, t, yh);
        Fp.combine(t, sv, 1, yh, -1, t, o);
        Fp.reduceWide(t, o, t, SUM + Y);                        // Y3 = s (X1 H^2 - X3) - Y1 H^3
        Fp.mul(p, Z, t, h, t, SUM + Z);                         // Z3 = Z1 H
        return zeroBit(t, h) & zeroBit(t, s);
    }

    // 1 if the element of F_q at xOff is 0, and 0 if not, all its limbs read
    private static int zeroBit(int[] x, int xOff)
    {
        int d = 0;
        for (int i = 0; i < Fp.SIZE; ++i)
        {
            d |= x[xOff + i];
        }
        return 1 + ((d | -d) >> 31);
    }

    // the affine coordinates x || y of the n Jacobian points in p, none at infinity, into z from zOff,
    // by one inversion of the product of their Z coordinates, Montgomery's trick; the points are made
    // from a random representative, whose factor the product carries
    private static void normalize(int[] p, int n, int[] z, int zOff, int[] t)
    {
        int[] c = new int[n * Fp.SIZE];
        System.arraycopy(p, Z, c, 0, Fp.SIZE);
        for (int i = 1; i < n; ++i)
        {
            Fp.mul(c, (i - 1) * Fp.SIZE, p, i * POINT + Z, c, i * Fp.SIZE);   // Z_0 Z_1 up to Z_i
        }
        int u = 0, zi = Fp.SIZE;
        Fp.inv(c, (n - 1) * Fp.SIZE, t, u);
        for (int i = n - 1; i > 0; --i)
        {
            Fp.mul(t, u, c, (i - 1) * Fp.SIZE, t, zi);          // Z_i^-1
            Fp.mul(t, u, p, i * POINT + Z, t, u);               // (Z_0 Z_1 up to Z_(i-1))^-1
            affine(p, i * POINT, t, zi, z, zOff + i * AFFINE);
        }
        affine(p, 0, t, u, z, zOff);
        Arrays.clear(c);
    }

    // x || y = (X Z^-2, Y Z^-3) into z from zOff for the Jacobian point at pOff in p and Z^-1 at ziOff in
    // t, whose limbs from 2 Fp.SIZE to 4 Fp.SIZE it takes as scratch
    private static void affine(int[] p, int pOff, int[] t, int ziOff, int[] z, int zOff)
    {
        int zi2 = 2 * Fp.SIZE, zi3 = 3 * Fp.SIZE;
        Fp.sqr(t, ziOff, t, zi2);
        Fp.mul(t, zi2, t, ziOff, t, zi3);
        Fp.mul(p, pOff + X, t, zi2, z, zOff + X);
        Fp.mul(p, pOff + Y, t, zi3, z, zOff + Y);
    }

    // p's affine coordinates x || y, as elements of F_q given as Fp holds one, into z from zOff, for p
    // not at infinity; read through the field's encoding, as the point's own encoding reads them, and
    // Fp.decode, rather than through Fp.fromBigInteger, which is for public values
    private static void affineCoordinates(ECPoint p, int[] z, int zOff)
    {
        ECPoint a = p.normalize();
        byte[] b = new byte[32];
        a.getAffineXCoord().encodeTo(b, 0);
        Fp.decode(b, 0, z, zOff + X);
        a.getAffineYCoord().encodeTo(b, 0);
        Fp.decode(b, 0, z, zOff + Y);
        Arrays.clear(b);
    }

    // (x z^2, y z^3, z) into p for the affine point x || y at aOff in a and a random non-zero z of F_q
    // drawn for the call
    private static void randomRepresentative(int[] a, int aOff, int[] p, int[] t)
    {
        int zz = 0;
        Fp.randomNonZero(CryptoServicesRegistrar.getSecureRandom(), p, Z);
        Fp.sqr(p, Z, t, zz);
        Fp.mul(a, aOff + X, t, zz, p, X);
        Fp.mul(t, zz, p, Z, t, zz);
        Fp.mul(a, aOff + Y, t, zz, p, Y);
    }

    // the point of the given curve that the Jacobian point p stands for: its Z is inverted once,
    // blinded by a random non-zero factor b as ECPoint.normalize() blinds it, as (Z b)^-1 b, and its
    // coordinates are handed over through their encoding; the point at infinity if Z is 0
    private static ECPoint toPoint(ECCurve curve, int[] p, int[] t)
    {
        if (zeroBit(p, Z) != 0)
        {
            return curve.getInfinity();
        }
        int b = 0, zi = Fp.SIZE, w = 4 * Fp.SIZE;
        Fp.randomNonZero(CryptoServicesRegistrar.getSecureRandom(), t, b);
        Fp.mul(p, Z, t, b, t, zi);
        Fp.inv(t, zi, t, zi);
        Fp.mul(t, zi, t, b, t, zi);                             // Z^-1
        affine(p, 0, t, zi, t, w);
        byte[] enc = new byte[64];
        Fp.encode(t, w + X, enc, 0);
        Fp.encode(t, w + Y, enc, 32);
        ECPoint r = curve.createPoint(new BigInteger(1, Arrays.copyOfRange(enc, 0, 32)),
            new BigInteger(1, Arrays.copyOfRange(enc, 32, 64)));
        Arrays.clear(enc);
        return r;
    }

    private SM9G1Multiplier()
    {
    }
}
