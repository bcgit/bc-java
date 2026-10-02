package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * The SM9 R-ate pairing e: G1 x G2 -&gt; G_T over the 256-bit BN curve
 * (GM/T 0044.5-2016). Computed as the optimal-ate/R-ate Miller loop with loop
 * parameter 6t+2, a two-term Frobenius tail, and the final exponentiation
 * f^((q^12-1)/N).
 * <p>
 * The Miller loop runs over the non-adjacent form of 6t+2, on the twist E'(F_p2) itself, in
 * homogeneous projective coordinates, and evaluates each line at P as a sparse element of F_p12 -
 * see {@code lines}. The Frobenius images of Q are the conjugates of its coordinates times
 * constants, and the final exponentiation is split in two: f^((q^6 - 1)(q^2 + 1)) by the
 * Frobenius, which costs one inversion, and the rest, (q^4 - q^2 + 1)/N, 767 bits of the 2811-bit
 * exponent, by three exponentiations by the 63-bit BN parameter t and the Frobenius - see
 * {@code hardPart}.
 * <p>
 * On the decryption, KEM and key-exchange paths the second argument is the user's private
 * key, and the first is chosen by whoever supplied the ciphertext or the ephemeral value.
 * The F_p arithmetic underneath, {@link Fp}'s, runs in constant time, and the loop does not
 * start from Q but from a random representative of it, (x Z, y Z, Z) for a non-zero Z drawn
 * afresh for each call: every coordinate and every line value derived from the key then carries
 * a random factor that no two calls share, and an observer choosing the first argument has no
 * fixed secret operand to average measurements against. The factors lie in F_p2, which the first
 * step of the final exponentiation annihilates, so the result is unchanged; the value the
 * exponentiation runs on is given a random factor of its own before that step, one the
 * exponentiation annihilates in turn - see {@code finalExponentiation}.
 * The lines through Q and -Q, and through the Frobenius images of Q, which are computed from Q as
 * it is, take the affine coordinates of those points as they are - values fixed by the key, though
 * not touched by the first argument.
 * <p>
 * The first argument is the point the loop's lines are evaluated at, and {@link #pairing}
 * evaluates them at its affine coordinates, the same two values in every line of every call: it
 * takes that point to be public.
 * <p>
 * {@link #multiPair} takes a product of pairings in one Miller loop and one final exponentiation,
 * for signature verification and for the pairing value a master public key fixes, without this
 * randomisation: its arguments must all be public.
 */
public class SM9Pairing
{
    private static final BigInteger Q = Fp.Q;

    /**
     * gamma = w^(q - 1) = (w^12)^((q - 1)/12) = (-2)^((q - 1)/12): w^12 = v^4 = u^2 = -2, and 12
     * divides q - 1, so gamma lies in F_q, with gamma^12 = 1 and gamma^6 = -1 (-2 is not a square
     * mod q, which is what makes u^2 + 2 irreducible). Every Frobenius constant below is a power of
     * it, and gamma^-k is gamma^(12 - k).
     */
    private static final BigInteger GAMMA = Q.subtract(BigInteger.valueOf(2))
        .modPow(Q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(12)), Q);

    // The Frobenius images of Q on the twist: psi(x, y) = (x w^-2, y w^-3) raised to q and carried
    // back by w^2 and w^3 is (x^q gamma^-2, y^q gamma^-3), and to q^2 it is (x gamma^-4, y gamma^-6),
    // x^q being the conjugate of x in F_p2 and x^(q^2) x itself, and gamma^-6 = -1. The first image
    // is also the map SM9G2Point.isInSubgroup tests G2 by.
    static final Fp2 FROB1_X = gammaPower(10);
    static final Fp2 FROB1_Y = gammaPower(9);
    private static final Fp2 FROB2_X = gammaPower(8);

    // w^q = gamma w and v^q = (w^q)^3 = gamma^3 v, so the q-power Frobenius takes w^i v^j to
    // gamma^(i + 3j) w^i v^j; w^(q^2) = gamma^2 w, so (w^2)^(q^2) = gamma^4 w^2
    private static final Fp2 GAMMA1 = gammaPower(1);
    private static final Fp2 GAMMA2 = gammaPower(2);
    private static final Fp2 GAMMA3 = gammaPower(3);
    private static final Fp2 GAMMA4 = gammaPower(4);
    private static final Fp2 GAMMA5 = gammaPower(5);

    private static Fp2 gammaPower(int k)
    {
        return new Fp2(GAMMA.modPow(BigInteger.valueOf(k), Q), BigInteger.ZERO);
    }

    // the offsets of the coordinates X, Y and Z of T, the point the lines of the Miller loop are
    // formed from, in its limbs, the size of T, and the size of a line's coefficients c0 || cY || cX
    private static final int X = 0, Y = Fp2.SIZE, Z = 2 * Fp2.SIZE, POINT = 3 * Fp2.SIZE, LINE = 3 * Fp2.SIZE;

    // the scratch lineDouble and lineAdd take
    private static final int LINE_SCRATCH = 11 * Fp.WIDE + 8 * Fp2.SIZE + Fp2.MUL_SCRATCH;

    // the scratch millerLoop takes: a line's value, l0 in F_p4 and l2 in F_p2 - see line - and the
    // scratch of the sparse product that multiplies it in, which the square's fits in as well
    private static final int LOOP_SCRATCH = Fp4.SIZE + Fp2.SIZE + Fp12.MUL_SPARSE_SCRATCH;

    /**
     * Doubles T = (X, Y, Z) in place - homogeneous projective coordinates on the twist
     * y^2 = x^3 + b', b' = 5u, so x = X/Z and y = Y/Z - and writes into l from lOff the coefficients
     * c0 || cY || cX of the tangent at T, whose value at P = (xP, yP) is c0 + cY yP v - cX xP w^2, as
     * {@link #line} multiplies it in. T is in t, from X, Y and Z, and s is scratch of LINE_SCRATCH
     * limbs.
     * <p>
     * On the image of the twist in E(F_p12) the tangent at T has slope lambda w^-1, with
     * lambda = 3x^2 / 2y the slope on the twist, and its value at P is
     * yP - y w^-3 - lambda w^-1 (xP - x w^-2). Times v = w^3 that is
     * (lambda x - y) + yP v - lambda xP w^2, and times 2YZ as well, clearing the denominators of
     * y and lambda = 3X^2 / 2YZ, it is (Y^2 - 3b'Z^2) + 2YZ yP v - 3X^2 xP w^2: T is on the curve,
     * Y^2 Z = X^3 + b'Z^3, so 3X^3 - 2Y^2 Z = Z(Y^2 - 3b'Z^2). The factor v 2YZ lies in F_p4, and
     * q^4 - 1 divides the final exponent (q^12 - 1) / N, so the final exponentiation takes it to 1.
     * <p>
     * The double is Costello, Lange and Naehrig's, times 4: X3 = 2XY (Y^2 - 9b'Z^2),
     * Y3 = (Y^2 + 9b'Z^2)^2 - 108 b'^2 Z^4 and Z3 = 8Y^3 Z. With the line it takes seven squares in
     * F_p2, 2XY and 2YZ among them as (X + Y)^2 - X^2 - Y^2 and (Y + Z)^2 - Y^2 - Z^2, and two
     * products, where the Jacobian doubling and its line took six squares and five products. The
     * squares and the product Y^2 2YZ are formed in full, as {@link Fp2#sqrWide} and
     * {@link Fp2#mulWide} form them, and each coefficient of the sums and multiples of them the
     * formulas take - 2YZ, 2XY, 3b'Z^2 = 15u Z^2, Y3 = (Y^2 + 9b'Z^2)^2 - 12(3b'Z^2)^2,
     * Z3 = 4Y^2 2YZ and 3X^2 - is formed from them unreduced and reduced once: sixteen reductions
     * where the doubling and its line took eighteen, and fourteen additions and subtractions in F_q
     * where they took forty-nine. Every wide value lies between -60q^2 and 25q^2.
     */
    private static void lineDouble(int[] t, int[] l, int lOff, int[] s)
    {
        int n = Fp2.SIZE, w = Fp.WIDE, k = Fp.SIZE;
        int a = 0, bb = a + 2 * w, c = bb + 2 * w, sq = c + 2 * w, ee = sq + 2 * w;
        int b = ee + 2 * w, h = b + n, e = h + n, f = e + n, sum = f + n, xy = sum + n, d = xy + n;
        int o = d + n, tt = o + w;

        Fp2.sqrWide(t, X, s, a, s, tt);                         // X^2
        Fp2.sqrWide(t, Y, s, bb, s, tt);                        // Y^2
        Fp.reduceWide(s, bb, s, b);
        Fp.reduceWide(s, bb + w, s, b + k);
        Fp2.sqrWide(t, Z, s, c, s, tt);                         // Z^2
        Fp2.add(t, Y, t, Z, s, sum);
        Fp2.sqrWide(s, sum, s, sq, s, tt);

        // 2YZ = (Y + Z)^2 - Y^2 - Z^2
        Fp.combine(s, sq, 1, bb, -1, c, -1, s, o);
        Fp.reduceWide(s, o, s, h);
        Fp.combine(s, sq + w, 1, bb + w, -1, c + w, -1, s, o);
        Fp.reduceWide(s, o, s, h + k);

        // 3b'Z^2 = 15u Z^2 = -30 c_1 + 15 c_0 u for Z^2 = c_0 + c_1 u, and 9b'Z^2
        Fp.combine(s, c + w, -30, s, o);
        Fp.reduceWide(s, o, s, e);
        Fp.combine(s, c, 15, s, o);
        Fp.reduceWide(s, o, s, e + k);
        Fp2.add(s, e, s, e, s, f);
        Fp2.add(s, f, s, e, s, f);

        // 2XY = (X + Y)^2 - X^2 - Y^2, and X3 = 2XY (Y^2 - 9b'Z^2)
        Fp2.add(t, X, t, Y, s, sum);
        Fp2.sqrWide(s, sum, s, sq, s, tt);
        Fp.combine(s, sq, 1, a, -1, bb, -1, s, o);
        Fp.reduceWide(s, o, s, xy);
        Fp.combine(s, sq + w, 1, a + w, -1, bb + w, -1, s, o);
        Fp.reduceWide(s, o, s, xy + k);
        Fp2.sub(s, b, s, f, s, d);
        Fp2.mul(s, xy, s, d, t, X, s, tt);

        // Y3 = (Y^2 + 9b'Z^2)^2 - 12(3b'Z^2)^2
        Fp2.add(s, b, s, f, s, sum);
        Fp2.sqrWide(s, sum, s, sq, s, tt);
        Fp2.sqrWide(s, e, s, ee, s, tt);
        Fp.combine(s, sq, 1, ee, -12, s, o);
        Fp.reduceWide(s, o, t, Y);
        Fp.combine(s, sq + w, 1, ee + w, -12, s, o);
        Fp.reduceWide(s, o, t, Y + k);

        // Z3 = 4Y^2 2YZ
        Fp2.mulWide(s, b, s, h, s, sq, s, tt);
        Fp.combine(s, sq, 4, s, o);
        Fp.reduceWide(s, o, t, Z);
        Fp.combine(s, sq + w, 4, s, o);
        Fp.reduceWide(s, o, t, Z + k);
        checkZ(t);

        // the tangent: Y^2 - 3b'Z^2, 2YZ and 3X^2
        Fp2.sub(s, b, s, e, l, lOff);
        System.arraycopy(s, h, l, lOff + n, n);
        Fp.combine(s, a, 3, s, o);
        Fp.reduceWide(s, o, l, lOff + 2 * n);
        Fp.combine(s, a + w, 3, s, o);
        Fp.reduceWide(s, o, l, lOff + 2 * n + k);
    }

    /**
     * Adds the affine twist point (x2, y2), elements of F_p2 from offset 0, to T in place and writes
     * into l from lOff the coefficients of the line through the two, as {@link #lineDouble} does for
     * the tangent. With R = y2 Z - Y and H = x2 Z - X the slope on the twist is lambda = R / H, and
     * taking the line through (x2, y2) the value at P, times v as in {@link #lineDouble}, is
     * (lambda x2 - y2) + yP v - lambda xP w^2; times H it is (R x2 - H y2) + H yP v - R xP w^2, off by
     * the factor v H in F_p4. The sum is X3 = H A, Y3 = R(X H^2 - A) - Y H^3 and Z3 = Z H^3, for
     * A = R^2 Z - H^3 - 2X H^2: with the line, two squares in F_p2 and eleven products, where the
     * Jacobian addition and its line took three squares and ten products. A, Y3 and the line's
     * R x2 - H y2 are formed from products formed in full, unreduced, and reduced once, as
     * {@link #lineDouble} forms its sums: twenty-two reductions where the addition and its line took
     * twenty-six, and six additions and subtractions in F_q where they took sixteen. Every wide value
     * lies between -5q^2 and 7q^2.
     */
    private static void lineAdd(int[] t, int[] x2, int[] y2, int[] l, int lOff, int[] s)
    {
        int n = Fp2.SIZE, w = Fp.WIDE, k = Fp.SIZE;
        int h3 = 0, xh2 = h3 + 2 * w, r2z = xh2 + 2 * w, p = r2z + 2 * w, yh3 = p + 2 * w;
        int r = yh3 + 2 * w, h = r + n, hh = h + n, hhh = hh + n, v = hhh + n, a = v + n, rr = a + n;
        int va = rr + n, o = va + n, tt = o + w;

        Fp2.mul(y2, 0, t, Z, s, r, s, tt);
        Fp2.sub(s, r, t, Y, s, r);                              // R = y2 Z - Y
        Fp2.mul(x2, 0, t, Z, s, h, s, tt);
        Fp2.sub(s, h, t, X, s, h);                              // H = x2 Z - X
        Fp2.sqr(s, h, s, hh, s, tt);
        Fp2.mulWide(s, h, s, hh, s, h3, s, tt);                 // H^3
        Fp.reduceWide(s, h3, s, hhh);
        Fp.reduceWide(s, h3 + w, s, hhh + k);
        Fp2.mulWide(t, X, s, hh, s, xh2, s, tt);                // X H^2
        Fp.reduceWide(s, xh2, s, v);
        Fp.reduceWide(s, xh2 + w, s, v + k);
        Fp2.sqr(s, r, s, rr, s, tt);
        Fp2.mulWide(s, rr, t, Z, s, r2z, s, tt);                // R^2 Z

        // A = R^2 Z - H^3 - 2X H^2
        Fp.combine(s, r2z, 1, h3, -1, xh2, -2, s, o);
        Fp.reduceWide(s, o, s, a);
        Fp.combine(s, r2z + w, 1, h3 + w, -1, xh2 + w, -2, s, o);
        Fp.reduceWide(s, o, s, a + k);

        // Y3 = R(X H^2 - A) - Y H^3, X3 = H A and Z3 = Z H^3
        Fp2.sub(s, v, s, a, s, va);
        Fp2.mulWide(s, r, s, va, s, p, s, tt);
        Fp2.mulWide(t, Y, s, hhh, s, yh3, s, tt);
        Fp.combine(s, p, 1, yh3, -1, s, o);
        Fp.reduceWide(s, o, t, Y);
        Fp.combine(s, p + w, 1, yh3 + w, -1, s, o);
        Fp.reduceWide(s, o, t, Y + k);
        Fp2.mul(s, h, s, a, t, X, s, tt);
        Fp2.mul(t, Z, s, hhh, t, Z, s, tt);
        checkZ(t);

        // the line: R x2 - H y2, H and R
        Fp2.mulWide(s, r, x2, 0, s, p, s, tt);
        Fp2.mulWide(s, h, y2, 0, s, yh3, s, tt);
        Fp.combine(s, p, 1, yh3, -1, s, o);
        Fp.reduceWide(s, o, l, lOff);
        Fp.combine(s, p + w, 1, yh3 + w, -1, s, o);
        Fp.reduceWide(s, o, l, lOff + k);
        System.arraycopy(s, h, l, lOff + n, n);
        System.arraycopy(s, r, l, lOff + 2 * n, n);
    }

    private static void checkZ(int[] t)
    {
        if (Fp2.zeroBit(t, Z) != 0)
        {
            // a doubling at a point of order 2 or an addition of T and +/-Q: neither occurs for a
            // Q of the odd-order subgroup G2, and the line through them has no meaning here
            throw new IllegalArgumentException("SM9 pairing second argument is not a point of G2");
        }
    }

    // f times c0 + (cY yP) v - (cX xP) w^2 for the coefficients c0 || cY || cX above, from lOff in l,
    // the one shape a line value takes, which has no w term and no v w^2 term and so is multiplied in
    // by the sparse product. xP and yP lie in F_q and are given as Fp holds an element of it, xP
    // negated, so that each product by one is two F_q products, where a product in F_p2 takes three,
    // and no line is negated; P is given as coordinates gives it, -xP and yP. f is multiplied in
    // place, on the scratch t of LOOP_SCRATCH limbs, which holds the line's value, l0 + l2 w^2, from
    // its start; f is null for the Miller loop's first line, standing for the 1 the loop's running
    // value starts at, and a new array holding the line's value itself is returned
    private static int[] line(int[] f, int[] l, int lOff, int[][] p, int[] t)
    {
        int l0 = 0, l2 = l0 + Fp4.SIZE, s = l2 + Fp2.SIZE;
        System.arraycopy(l, lOff, t, l0, Fp2.SIZE);
        Fp2.mulFp(l, lOff + Fp2.SIZE, p[1], 0, t, l0 + Fp2.SIZE);
        Fp2.mulFp(l, lOff + 2 * Fp2.SIZE, p[0], 0, t, l2);
        if (f == null)
        {
            f = new int[Fp12.SIZE];
            System.arraycopy(t, l0, f, 0, Fp4.SIZE);
            System.arraycopy(t, l2, f, 2 * Fp4.SIZE, Fp2.SIZE);
        }
        else
        {
            Fp12.mulSparse(f, 0, t, l0, t, l2, f, 0, t, s);
        }
        return f;
    }

    // -x and y for the affine coordinates (x, y) of a point of G1, as elements of F_q given as Fp
    // holds one, for line
    private static int[][] coordinates(ECPoint p)
    {
        int[] negX = new int[Fp.SIZE], y = new int[Fp.SIZE];
        Fp.fromBigInteger(p.getAffineXCoord().toBigInteger().negate(), negX, 0);
        Fp.fromBigInteger(p.getAffineYCoord().toBigInteger(), y, 0);
        return new int[][]{ negX, y };
    }

    // SM9Curve.LOOP, 6t + 2, in non-adjacent form, least significant digit first: of its sixty-six
    // digits, each 1, -1 or 0, eleven are not 0, five of them -1, where 6t + 2 has sixteen bits set
    private static final byte[] LOOP_NAF = WNafUtil.generateNaf(SM9Curve.LOOP);

    // the number of lines in a Miller loop: a tangent for each digit of LOOP_NAF below its top one,
    // a line through Q or -Q for each of those that is not 0, and the two Frobenius lines, which
    // comes to LOOP_NAF's length plus the number of its digits that are not 0: seventy-seven
    private static final int LINES = LOOP_NAF.length + nonZeroDigits(LOOP_NAF);

    // the number of the digits of a non-adjacent form, each 1, -1 or 0, that are not 0
    private static int nonZeroDigits(byte[] naf)
    {
        int count = 0;
        for (int i = 0; i != naf.length; ++i)
        {
            count += naf[i] & 1;
        }
        return count;
    }

    /**
     * The coefficients of the lines of Q's Miller loop, LINE limbs each, from T, given as
     * {@link #lineDouble} takes it, which it updates, in the order the loop multiplies them in: at
     * each digit of LOOP_NAF below its top one the tangent, and the line through Q when the digit is
     * 1, or through -Q = (x, -y) when it is -1, then the two lines of the Frobenius tail -
     * R-ate/optimal-ate: Q1 = pi(Q) = (x^q gamma^-2, y^q gamma^-3) added, and
     * Q2 = pi^2(Q) = (x gamma^-4, -y) subtracted, which is adding (x gamma^-4, y). They depend on Q
     * and T's starting point alone, not on P.
     * <p>
     * The non-adjacent form of 6t + 2 has ten digits that are not 0 below its top one, where its
     * binary form has fifteen bits set, so the loop takes ten lines through Q or -Q where it took
     * fifteen through Q. Miller's algorithm divides at each step by the vertical line through the
     * point it reaches, and where it subtracts Q by the one through Q as well; the loop leaves all of
     * them out, since their values at P, xP - x w^-2 for a point (x, y) of the twist, lie in F_p6,
     * w^-2 being w^4 / u, and q^6 - 1 divides the final exponent. The pairing is the one the binary
     * form gives.
     */
    private static int[] lines(int[] t, SM9G2Point q)
    {
        int[] l = new int[LINES * LINE], s = new int[LINE_SCRATCH];
        int[] x = q.x.limbs, y = q.y.limbs, negY = q.y.negate().limbs;
        int k = 0;
        for (int i = LOOP_NAF.length - 2; i >= 0; --i)
        {
            lineDouble(t, l, k++ * LINE, s);
            if (LOOP_NAF[i] != 0)
            {
                lineAdd(t, x, LOOP_NAF[i] > 0 ? y : negY, l, k++ * LINE, s);
            }
        }
        int[] x1 = q.x.conjugate().multiply(FROB1_X).limbs, y1 = q.y.conjugate().multiply(FROB1_Y).limbs;
        lineAdd(t, x1, y1, l, k++ * LINE, s);
        lineAdd(t, q.x.multiply(FROB2_X).limbs, y, l, k * LINE, s);
        Arrays.clear(s);
        return l;
    }

    /**
     * The lines of Q's Miller loop from Q itself, T = (x, y, 1), computed on the first call for a Q
     * and kept with it. For {@link #multiPair}, whose Q are public: P2, or a master public key,
     * whose lines verification would otherwise recompute for every signature.
     */
    private static int[] publicLines(SM9G2Point q)
    {
        int[] l = q.millerLines;
        if (l == null)
        {
            int[] t = new int[POINT];
            System.arraycopy(q.x.limbs, 0, t, X, Fp2.SIZE);
            System.arraycopy(q.y.limbs, 0, t, Y, Fp2.SIZE);
            System.arraycopy(Fp2.ONE.limbs, 0, t, Z, Fp2.SIZE);
            l = lines(t, q);
            q.millerLines = l;
        }
        return l;
    }

    /**
     * e(P, Q) for P in G1 (a point of E(F_q)) and Q in G2 (a point of the twist). P is taken to be
     * public.
     */
    public static Fp12 pairing(ECPoint p, SM9G2Point q)
    {
        checkArguments(p, q);
        return pair(coordinates(p.normalize()), q);
    }

    private static void checkArguments(ECPoint p, SM9G2Point q)
    {
        // Both arguments are validated here rather than by every caller. e is only defined on
        // G1 x G2: at infinity on either side the Miller loop reads affine coordinates that do
        // not exist, which used to surface as a NullPointerException, and a point of a foreign
        // curve was paired with no complaint at all. G1 has cofactor 1, so on-curve and not
        // infinite settles membership there. The G2 side is checked for infinity only: every G2
        // point that reaches here has come through SM9G2Point.decode, which makes the subgroup
        // test once per key - under a sixth of a pairing - so a caller assembling one through
        // add or multiply should call SM9G2Point.isInSubgroup itself.
        if (p == null || q == null)
        {
            throw new NullPointerException("SM9 pairing arguments cannot be null");
        }
        if (p.isInfinity() || !SM9Curve.G1.equals(p.getCurve()) || !p.isValid())
        {
            throw new IllegalArgumentException("SM9 pairing first argument is not a point of G1");
        }
        if (q.isInfinity())
        {
            throw new IllegalArgumentException("SM9 pairing second argument is not a point of G2");
        }
    }

    // e(P, Q) for P given as coordinates gives it
    private static Fp12 pair(int[][] p, SM9G2Point q)
    {
        // T starts at a random representative of Q rather than at Q - see the class javadoc
        Fp2 z = Fp2.randomNonZero();
        int[] t = new int[POINT];
        System.arraycopy(q.x.multiply(z).limbs, 0, t, X, Fp2.SIZE);
        System.arraycopy(q.y.multiply(z).limbs, 0, t, Y, Fp2.SIZE);
        System.arraycopy(z.limbs, 0, t, Z, Fp2.SIZE);
        int[] l = lines(t, q);

        Fp12 f = millerLoop(new int[][][]{ p }, new int[][]{ l }, 1);
        Arrays.clear(t);
        Arrays.clear(l);
        return finalExponentiation(f);
    }

    /**
     * The product e(P_0, Q_0) e(P_1, Q_1) ... of the pairings of p[i] in G1 and q[i] in G2, in one
     * Miller loop, whose squarings the pairs share, and one final exponentiation. Signature
     * verification's w' = e(S, [h1]P2 + P_pub-s) g^h is, by bilinearity,
     * e([h1]S, P2) e(S + [h]P1, P_pub-s), which this gives in about the time of one
     * {@link #pairing}; and the pairing value a master public key fixes, e(P_pub-e, P2) or
     * e(P1, P_pub-s), whose arguments are public as well, is the product of one pair.
     * <p>
     * <b>For public arguments only.</b> Unlike {@link #pairing}, it does not randomise its
     * operands: the Miller loop starts from each Q itself and the final exponentiation takes no
     * random factor, so every value it works on is fixed by its arguments, and a private key passed
     * here would be exposed to whoever can observe the computation. The lines of each Q's loop
     * depend on Q alone, so they are computed on the Q's first use here and kept with it - P2's
     * once, and a master public key's for as long as the key object lives - where {@link #pairing}
     * computes its point's afresh, from a random representative, on every call. A pair with either
     * point at infinity contributes 1; the G1 points are validated as {@link #pairing} validates its
     * first argument, and brought to affine coordinates without a random draw, and the G2 points,
     * like its second, are taken to be points of G2.
     */
    public static Fp12 multiPair(ECPoint[] p, SM9G2Point[] q)
    {
        if (p == null || q == null)
        {
            throw new NullPointerException("SM9 pairing arguments cannot be null");
        }
        if (p.length != q.length)
        {
            throw new IllegalArgumentException("SM9 multi-pairing needs as many G1 points as G2 points");
        }
        int[][][] c = new int[p.length][][];
        int[][] l = new int[p.length][];
        int n = 0;
        for (int i = 0; i != p.length; i++)
        {
            if (p[i] == null || q[i] == null)
            {
                throw new NullPointerException("SM9 pairing arguments cannot be null");
            }
            if (!SM9Curve.G1.equals(p[i].getCurve()) || !p[i].isValid())
            {
                throw new IllegalArgumentException("SM9 pairing first argument is not a point of G1");
            }
            if (p[i].isInfinity() || q[i].isInfinity())
            {
                continue;
            }
            // public, so brought to affine coordinates by normalizeAll, whose inversion takes no
            // random factor, rather than by ECPoint.normalize(), which draws one from the default
            // source - within a bound on SM9's own G1 curve, after which it throws, but on a curve
            // object of another class equal to G1, which the check above admits, without one, so
            // that for a source yielding only zeros or only ones it would never return
            ECPoint[] pn = { p[i] };
            p[i].getCurve().normalizeAll(pn);
            c[n] = coordinates(pn[0]);
            l[n] = publicLines(q[i]);
            ++n;
        }
        if (n == 0)
        {
            return Fp12.ONE;
        }
        return publicFinalExponentiation(millerLoop(c, l, n));
    }

    /**
     * The product of the Miller loops of the first n pairs (P_j, Q_j), n at least 1, P_j given by
     * its affine coordinates, x negated, as {@link #coordinates} gives them, and Q_j by the
     * coefficients of its loop's lines, as {@link #lines} lists them: each step squares the
     * running value once for all of them. The running value starts at 1, which the first step would
     * square and then multiply by the first line: it starts at that line's value instead, and the
     * first step does not square it. It is squared and multiplied in place, on one scratch array for
     * the whole loop, which is erased at the end.
     */
    private static Fp12 millerLoop(int[][][] p, int[][] l, int n)
    {
        // null until the first line is multiplied in, standing for 1 - see line
        int[] f = null, t = new int[LOOP_SCRATCH];
        int k = 0;
        for (int i = LOOP_NAF.length - 2; i >= 0; --i)
        {
            if (f != null)
            {
                Fp12.sqr(f, 0, f, 0, t, 0);
            }
            for (int j = 0; j != n; ++j)
            {
                f = line(f, l[j], k * LINE, p[j], t);
            }
            ++k;
            if (LOOP_NAF[i] != 0)
            {
                for (int j = 0; j != n; ++j)
                {
                    f = line(f, l[j], k * LINE, p[j], t);
                }
                ++k;
            }
        }
        for (; k != LINES; ++k)
        {
            for (int j = 0; j != n; ++j)
            {
                f = line(f, l[j], k * LINE, p[j], t);
            }
        }
        Arrays.clear(t);
        return new Fp12(f);
    }

    /**
     * f^((q^12 - 1)/N), as (f^((q^6 - 1)(q^2 + 1)))^HARD with HARD = (q^4 - q^2 + 1)/N - N divides
     * q^4 - q^2 + 1, the twelfth cyclotomic polynomial at q: the first factor by the Frobenius, at
     * the cost of one inversion, and the second by {@link #hardPart}.
     * <p>
     * The random factors the Miller loop leaves in f - powers of the Z of the random representative
     * of Q that {@link #pairing} starts from - lie in F_p2, whose elements raised to q^6 - 1 give 1,
     * so the product f^(q^6) f^-1 the exponentiation starts with would give a value fixed by the
     * arguments - the user's key among them - for the steps after it to take as an operand. The
     * random factor rho - see {@link #hardPartKernel} - is therefore folded into f^-1 before that
     * product, which then gives f^(q^6 - 1) rho, so that from there on the exponentiation runs on a
     * random representative of that value, as the Miller loop runs on one of Q; what the first part
     * leaves of rho, the second takes to 1, and the result is unchanged. Folded into the product's
     * result, rho would leave that result, and the two steps that take it as an operand, fixed by
     * the arguments.
     */
    private static Fp12 finalExponentiation(Fp12 f)
    {
        int[] s = new int[Fp12.MUL_SCRATCH];
        Fp12 f1 = frobenius6(f).multiply(f.invert().multiply(hardPartKernel(), s), s);   // f^(q^6 - 1) rho
        Fp12 f2 = frobenius2(f1).multiply(f1, s);                       // (f^(q^6 - 1) rho)^(q^2 + 1)
        Arrays.clear(s);
        return hardPart(f2);                                            // (f^(q^6 - 1) rho)^((q^2 + 1) HARD)
    }

    /**
     * f^((q^12 - 1)/N) as {@link #finalExponentiation} takes it, without the random factor, for
     * an f that {@link #multiPair}'s public arguments fix.
     */
    private static Fp12 publicFinalExponentiation(Fp12 f)
    {
        int[] s = new int[Fp12.MUL_SCRATCH];
        Fp12 f1 = frobenius6(f).multiply(f.invert(), s);                // f^(q^6 - 1)
        Fp12 f2 = frobenius2(f1).multiply(f1, s);                       // f1^(q^2 + 1)
        Arrays.clear(s);
        return hardPart(f2);                                            // f1^((q^2 + 1) HARD)
    }

    /**
     * f^HARD for f in the cyclotomic subgroup, the subgroup of order q^4 - q^2 + 1 in which the first
     * part of the final exponentiation leaves its value. For the BN parameterisation
     * q = 36t^4 + 36t^3 + 24t^2 + 6t + 1, N = 36t^4 + 36t^3 + 18t^2 + 6t + 1, HARD is exactly
     * l3 q^3 + l2 q^2 + l1 q + l0 with l3 = 1, l2 = 6t^2 + 1, l1 = -36t^3 - 18t^2 - 12t + 1 and
     * l0 = -36t^3 - 30t^2 - 18t - 2, and raising to q, q^2 or q^3 is a Frobenius map. So, as Scott
     * et al. give it, f^HARD = y0 y1^2 y2^6 y3^12 y4^18 y5^30 y6^36 for y0 to y6 formed from f, f^t,
     * f^(t^2) and f^(t^3) by the Frobenius, products and inverses, and the chain below takes that
     * product in four squarings and nine products: three exponentiations by the 63-bit t where
     * {@link Fp12#pow} would take one by the 767-bit HARD. The value is the same, the expansion being
     * of HARD itself rather than of a multiple of it, and the inverses are conjugates, since
     * f^(q^6) = f^-1 in that subgroup.
     */
    private static Fp12 hardPart(Fp12 f)
    {
        Fp12 ft = powT(f);                                              // f^t
        Fp12 ft2 = powT(ft);                                            // f^(t^2)
        Fp12 ft3 = powT(ft2);                                           // f^(t^3)

        // the scratch of the products and squares below, made once for all of them
        int[] s = new int[Fp12.MUL_SCRATCH];
        Fp12 fq2 = frobenius2(f);
        Fp12 y0 = frobenius(f).multiply(fq2, s).multiply(frobenius(fq2), s);  // f^(q + q^2 + q^3)
        Fp12 y1 = frobenius6(f);                                        // f^-1
        Fp12 y2 = frobenius2(ft2);                                      // f^(t^2 q^2)
        Fp12 y3 = frobenius6(frobenius(ft));                            // f^-(t q)
        Fp12 y4 = frobenius6(ft.multiply(frobenius(ft2), s));           // f^-(t + t^2 q)
        Fp12 y5 = frobenius6(ft2);                                      // f^-(t^2)
        Fp12 y6 = frobenius6(ft3.multiply(frobenius(ft3), s));          // f^-(t^3 + t^3 q)

        Fp12 t0 = y6.cyclotomicSquare(s).multiply(y4, s).multiply(y5, s);  // y4 y5 y6^2
        Fp12 t1 = y3.multiply(y5, s).multiply(t0, s);                   // y3 y4 y5^2 y6^2
        t0 = t0.multiply(y2, s);                                        // y2 y4 y5 y6^2
        t1 = t1.cyclotomicSquare(s).multiply(t0, s).cyclotomicSquare(s);  // y2^2 y3^4 y4^6 y5^10 y6^12
        t0 = t1.multiply(y1, s);                                        // y1 y2^2 y3^4 y4^6 y5^10 y6^12
        t1 = t1.multiply(y0, s);                                        // y0 y2^2 y3^4 y4^6 y5^10 y6^12
        Fp12 z = t0.cyclotomicSquare(s).multiply(t1, s);                // y0 y1^2 y2^6 y3^12 y4^18 y5^30 y6^36
        Arrays.clear(s);
        return z;
    }

    /**
     * The random factor rho {@link #finalExponentiation} folds into the value it runs on, an element of
     * the subgroup of order HARD, in which what the first part of the final exponentiation leaves of
     * it, rho^(q^2 + 1), lies as well, for the second part to take to 1:
     * B^(e + 2^11 - 1), for a base B of that subgroup drawn once and kept - see {@link #kernelTable} -
     * and an e of 64 bits drawn for the call, taken by {@link #kernelPower} in ten squarings and ten
     * products, where drawing a uniform element of the subgroup, as {@link #randomKernelElement}
     * draws B, takes an inversion and two exponentiations by t. rho is thus one of 2^64 consecutive
     * powers of B, drawn independently for each call, rather than an element drawn uniformly from the
     * whole subgroup; the 2^11 - 1, which the comb's table adds, changes which powers they are and not
     * how one is drawn.
     */
    private static Fp12 hardPartKernel()
    {
        byte[] b = new byte[8];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(b);
        long e = Pack.bigEndianToLong(b, 0);
        Arrays.clear(b);
        return kernelPower(e);
    }

    /**
     * A random element of the subgroup of order HARD: y = z^((q^6 - 1)(q^2 + 1)) lies in the
     * subgroup of order q^4 - q^2 + 1 = N * HARD for any non-zero z, and y^N in the subgroup of order
     * HARD. N is q - 6t^2 exactly, so y^N = y^q (y^(t^2))^-6, the q-th power a Frobenius map and the
     * inverse a conjugate as in {@link #hardPart}: two exponentiations by the 63-bit t where
     * {@link Fp12#pow} would take one by the 256-bit N, for the same value.
     */
    private static Fp12 randomKernelElement()
    {
        Fp12 z = new Fp12(new Fp4(Fp2.randomNonZero(), Fp2.randomNonZero()),
            new Fp4(Fp2.randomNonZero(), Fp2.randomNonZero()), new Fp4(Fp2.randomNonZero(), Fp2.randomNonZero()));
        Fp12 z1 = frobenius6(z).multiply(z.invert());
        Fp12 y = frobenius2(z1).multiply(z1);                           // z^((q^6 - 1)(q^2 + 1))
        Fp12 s = powT(powT(y));                                         // y^(t^2)
        s = s.cyclotomicSquare().multiply(s).cyclotomicSquare();        // y^(6t^2)
        return frobenius(y).multiply(frobenius6(s));                    // y^(q - 6t^2) = y^N
    }

    // kernelPower's comb reads e in COMB_SPACING columns of COMB_TEETH bits, spaced COMB_SPACING
    // apart, from a table of COMB_ENTRIES elements: 66 bits, the two past e's 64 being 0
    private static final int COMB_TEETH = 6, COMB_SPACING = 11, COMB_ENTRIES = 1 << COMB_TEETH;

    // kernelTable's table, made on the first call that needs it; guarded by KERNEL_TABLE_LOCK
    private static int[] kernelTable;
    private static final Object KERNEL_TABLE_LOCK = new Object();

    /**
     * The table {@link #kernelPower} reads, 24 KB: the sixty-four elements
     * B^(1 + d0 + d1 2^11 + d2 2^22 + d3 2^33 + d4 2^44 + d5 2^55) for
     * d = d0 + 2d1 + 4d2 + 8d3 + 16d4 + 32d5 from 0 to 63, B being a random element of the subgroup of
     * order HARD that {@link #randomKernelElement} draws from the default source on the first call,
     * and that is kept, in the table, for as long as the class is loaded. The 1 in each entry's
     * exponent makes entry 0 B rather than 1, an element all but one of whose twelve coefficients are
     * 0, which a column whose bits are all 0 would otherwise multiply in. A call whose draw fails
     * leaves no table behind, and the next call draws again.
     */
    private static int[] kernelTable()
    {
        synchronized (KERNEL_TABLE_LOCK)
        {
            if (kernelTable == null)
            {
                int[] table = new int[COMB_ENTRIES * Fp12.SIZE], t = new int[Fp12.MUL_SCRATCH];
                int[] b = randomKernelElement().limbs;
                System.arraycopy(b, 0, table, 0, Fp12.SIZE);
                for (int i = 0; i < COMB_TEETH; ++i)
                {
                    // b = B^(2^(11 i)), and the entries from 2^i to 2^(i + 1) - 1 are those below 2^i
                    // times b
                    for (int d = 0; d < 1 << i; ++d)
                    {
                        Fp12.mul(table, d * Fp12.SIZE, b, 0, table, ((1 << i) + d) * Fp12.SIZE, t, 0);
                    }
                    for (int s = 0; s < COMB_SPACING; ++s)
                    {
                        Fp12.cyclotomicSqr(b, 0, null, 0, b, 0, t, 0);
                    }
                }
                Arrays.clear(b);
                Arrays.clear(t);
                kernelTable = table;
            }
            return kernelTable;
        }
    }

    /**
     * B^(e + 2^11 - 1) for the base B of {@link #kernelTable}, e read as an unsigned 64-bit value, by
     * Lim and Lee's comb: e's bits fall into eleven columns of six, column c holding bits c, c + 11,
     * c + 22, c + 33, c + 44 and c + 55 - bits 64 and 65, in the top two columns, lying past e and
     * taken as 0 - which pick out the entry T_c of the table that is B times the product of the
     * B^(2^(11 i)) whose bits are set, and the product of the T_c^(2^c) is B^e times the B^(2^c)
     * each entry's factor B contributes, B^(2^11 - 1) in all. From the top column down, each column
     * squares the running value and multiplies its entry in - ten squarings and ten products
     * whatever e is - and each entry is read out of the table in full, through {@link Fp12#lookup},
     * so that neither the operations nor the memory they read depend on e. Each column's scan
     * starts at an entry drawn at random for it, one byte each of an eleven-byte draw the call
     * makes, and wraps round, and the value it reads into is cleared first, so that the step of the
     * scan that moves the column's entry into place does not give the column's bits away either.
     */
    private static Fp12 kernelPower(long e)
    {
        int[] table = kernelTable();

        // the entry each column's lookup starts its scan at, a byte drawn for it
        byte[] starts = new byte[COMB_SPACING];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(starts);

        int[] r = new int[Fp12.SIZE], x = new int[Fp12.SIZE], t = new int[Fp12.MUL_SCRATCH];
        Fp12.lookup(table, COMB_ENTRIES, column(e, COMB_SPACING - 1), starts[COMB_SPACING - 1], r);
        for (int c = COMB_SPACING - 2; c >= 0; --c)
        {
            Fp12.cyclotomicSqr(r, 0, null, 0, r, 0, t, 0);
            Fp12.lookup(table, COMB_ENTRIES, column(e, c), starts[c], x);
            Fp12.mul(r, 0, x, 0, r, 0, t, 0);
        }
        Arrays.clear(starts);
        Arrays.clear(x);
        Arrays.clear(t);
        return new Fp12(r);
    }

    // column c of kernelPower's comb over e: bits c, c + 11, ..., c + 55, as the index of a table
    // entry, a bit past e's 64 - which e >>> would read as bit 0 or 1 - masked to 0
    private static int column(long e, int c)
    {
        int d = 0;
        for (int i = COMB_TEETH - 1; i >= 0; --i)
        {
            int bit = c + i * COMB_SPACING;
            d = (d << 1) | ((int)(e >>> bit) & 1 & ((bit - 64) >> 31));
        }
        return d;
    }

    // SM9Curve.T in non-adjacent form, least significant digit first: of its sixty-four digits, each
    // 1, -1 or 0, eleven are not 0, where t has fourteen bits set. powT raises to t over it, and
    // SM9G2Point.isInSubgroup multiplies by t over it
    static final byte[] T_NAF = WNafUtil.generateNaf(SM9Curve.T);

    /**
     * y^t for y in the cyclotomic subgroup, t being the BN parameter, which is public: y's successive
     * squares are formed in Karabina's compressed form, in four F_p2 products each, and those at the
     * non-zero digits of t's non-adjacent form are decompressed together, with one inversion, and
     * multiplied together - conjugated where the digit is -1, the conjugate of an element of the
     * subgroup being its inverse. The squaring {@link Fp12#pow} uses takes nine F_p2 squares, and its
     * binary form of t fourteen products.
     */
    private static Fp12 powT(Fp12 y)
    {
        int count = 0;
        for (int i = 0; i != T_NAF.length; ++i)
        {
            count += T_NAF[i] & 1;
        }
        int[] c = new int[Fp12.COMPRESSED_SIZE], squares = new int[count * Fp12.COMPRESSED_SIZE];

        // the scratch of the compressed squarings and of the products below, sized for the larger
        int[] t = new int[Math.max(Fp12.MUL_SCRATCH, Fp12.COMPRESSED_SQR_SCRATCH)];
        System.arraycopy(y.limbs, 2 * Fp2.SIZE, c, 0, Fp12.COMPRESSED_SIZE);
        for (int i = 0, j = 0; i != T_NAF.length; ++i)
        {
            if (T_NAF[i] != 0)
            {
                System.arraycopy(c, 0, squares, j++ * Fp12.COMPRESSED_SIZE, Fp12.COMPRESSED_SIZE);
            }
            if (i != T_NAF.length - 1)
            {
                Fp12.compressedSqr(c, 0, c, 0, t, 0);
            }
        }
        Fp12[] y2i = Fp12.decompress(squares, count);
        Fp12 r = null;
        for (int i = 0, j = 0; i != T_NAF.length; ++i)
        {
            if (T_NAF[i] != 0)
            {
                Fp12 v = T_NAF[i] > 0 ? y2i[j] : frobenius6(y2i[j]);
                r = r == null ? v : r.multiply(v, t);
                ++j;
            }
        }
        Arrays.clear(c);
        Arrays.clear(squares);
        Arrays.clear(t);
        return r;
    }

    // the offsets of the six F_p2 coefficients of an element of F_p12, a0 + a1 v + (b0 + b1 v) w
    // + (c0 + c1 v) w^2, in its limbs
    private static final int A0 = 0, A1 = Fp2.SIZE, B0 = 2 * Fp2.SIZE, B1 = 3 * Fp2.SIZE, C0 = 4 * Fp2.SIZE,
        C1 = 5 * Fp2.SIZE;

    /**
     * z^(q^6): F_p2 is fixed, v^(q^6) = -v and w^(q^6) = gamma^6 w = -w.
     */
    private static Fp12 frobenius6(Fp12 z)
    {
        int[] r = Arrays.clone(z.limbs);
        Fp2.neg(r, A1, r, A1);
        Fp2.neg(r, B0, r, B0);
        Fp2.neg(r, C1, r, C1);
        return new Fp12(r);
    }

    /**
     * z^(q^2): F_p2 is fixed, v^(q^2) = -v and w^(q^2) = gamma^2 w.
     */
    static Fp12 frobenius2(Fp12 z)
    {
        int[] x = z.limbs, r = new int[Fp12.SIZE];
        System.arraycopy(x, A0, r, A0, Fp2.SIZE);
        Fp2.neg(x, A1, r, A1);
        Fp2.mulFp(x, B0, GAMMA2.limbs, 0, r, B0);
        Fp2.mulFp(x, B1, GAMMA2.limbs, 0, r, B1);
        Fp2.neg(r, B1, r, B1);
        Fp2.mulFp(x, C0, GAMMA4.limbs, 0, r, C0);
        Fp2.mulFp(x, C1, GAMMA4.limbs, 0, r, C1);
        Fp2.neg(r, C1, r, C1);
        return new Fp12(r);
    }

    /**
     * z^q: x^q is the conjugate of x in F_p2, v^q = gamma^3 v and w^q = gamma w.
     * {@link Fp12#powSecure} raises its base to q, q^2 and q^3 through this and {@link #frobenius2}.
     */
    static Fp12 frobenius(Fp12 z)
    {
        int[] x = z.limbs, r = new int[Fp12.SIZE];
        Fp2.conj(x, A0, r, A0);
        conjugateTimes(x, A1, GAMMA3, r);
        conjugateTimes(x, B0, GAMMA1, r);
        conjugateTimes(x, B1, GAMMA4, r);
        conjugateTimes(x, C0, GAMMA2, r);
        conjugateTimes(x, C1, GAMMA5, r);
        return new Fp12(r);
    }

    // r's F_p2 coefficient at off = the conjugate of x's times gamma, a power of GAMMA and so in F_q
    private static void conjugateTimes(int[] x, int off, Fp2 gamma, int[] r)
    {
        Fp2.conj(x, off, r, off);
        Fp2.mulFp(r, off, gamma.limbs, 0, r, off);
    }

    /**
     * Serialize a G_T element to bytes per GM/T 0044.5: high dimension first,
     * recursively over the 1-2-4-12 tower (w^2, w^1, w^0; then v^1, v^0; then
     * u^1, u^0), 32 bytes per F_q component; 384 bytes total.
     */
    public static byte[] toBytes(Fp12 z)
    {
        // the value serialised can be a secret - the pairing value a key is derived from - and
        // Fp.encode takes each coefficient out of Montgomery form in constant time and erases its
        // copy, as callers erase the array it is written into
        byte[] out = new byte[12 * 32];
        for (int i = 0; i < 12; ++i)
        {
            Fp.encode(z.limbs, (11 - i) * Fp.SIZE, out, 32 * i);
        }
        return out;
    }

    private SM9Pairing()
    {
    }
}
