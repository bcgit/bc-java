package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Optimal ate pairing on BLS12-381: a bilinear, non-degenerate map
 * {@code e: G1 x G2 -> GT} where GT is the order-r subgroup of Fp^12 ^*.
 * <ul>
 *   <li>The Miller loop keeps {@code T} on the twist {@code E'(Fp^2)} in
 *       homogeneous projective coordinates, so no step inverts, and
 *       evaluates each line at {@code P} directly as a sparse Fp^12 element
 *       with three non-zero Fp^2 coefficients, multiplied into the accumulator by
 *       {@link Fp12Element#mulBy014}. The lines are scaled by Fp^2 and Fp^4
 *       factors (the twist's {@code w^3} and the projective denominators); every
 *       such factor lies in a proper subfield of Fp^12, which the final
 *       exponentiation maps to 1, so the pairing value is unchanged.</li>
 *   <li>The final exponentiation splits into the Frobenius-based easy part and
 *       the hard part described at {@code finalExponentiation}.</li>
 * </ul>
 */
public class BLS12_381Pairing
{
    /** BLS12-381 trace parameter |x|: 0xd201000000010000. The actual x is negative. */
    private static final BigInteger ABS_X = new BigInteger("d201000000010000", 16);

    /**
     * Hard-part exponent {@code (p^4 - p^2 + 1) / r} (~1269 bits), applied
     * after the Frobenius-based easy part. The full final exponent
     * {@code (p^12 - 1) / r} (~4317 bits) factors as
     * {@code (p^6 - 1) * (p^2 + 1) * (p^4 - p^2 + 1) / r}; the easy part
     * computes {@code f^((p^6 - 1)(p^2 + 1))} essentially for free using
     * conjugation and one Frobenius&sup2; application, leaving only this
     * shorter exponent, which {@link #hardPart} applies by an addition chain
     * in x (kept for the tests that check that chain against a direct power).
     */
    public static final BigInteger HARD_EXPONENT = Fp2Element.P.pow(4)
        .subtract(Fp2Element.P.pow(2))
        .add(BigInteger.ONE)
        .divide(BLS12_381G1.ORDER);

    /** BLS12-381 trace parameter x = -{@link #ABS_X}. */
    private static final BigInteger X = ABS_X.negate();

    /**
     * {@code (1 - x) / 3 = (|x| + 1) / 3}, 63 bits: the cube-factor-free hard
     * part raises to {@code (x - 1)^2 / 3 = ((1 - x) / 3) * (|x| + 1)}. The
     * division is exact for the BLS12 family by construction.
     */
    private static final BigInteger ONE_MINUS_X_OVER_3;

    static
    {
        BigInteger[] divRem = BigInteger.ONE.subtract(X).divideAndRemainder(BigInteger.valueOf(3));
        if (divRem[1].signum() != 0)
        {
            throw new IllegalStateException("1 - x must be divisible by 3 for BLS12 family");
        }
        ONE_MINUS_X_OVER_3 = divRem[0];
    }

    private BLS12_381Pairing()
    {
    }

    /**
     * Compute the optimal ate pairing {@code e(P, Q)} for {@code P} on
     * BLS12-381 G1 and {@code Q} on BLS12-381 G2.
     *
     * @param g1 a point on the BLS12-381 G1 curve. Must be in the
     *           prime-order subgroup; this method does not subgroup-check.
     * @param g2 a point on the BLS12-381 G2 curve. Must be in the
     *           prime-order subgroup; this method does not subgroup-check.
     * @return {@code e(P, Q)} as an Fp^12 element in the order-r subgroup of
     *         Fp^12 ^*. Returns 1 if either input is the point at infinity.
     */
    public static Fp12Element pair(ECPoint g1, BLS12_381G2Point g2)
    {
        return multiPair(new ECPoint[]{g1}, new BLS12_381G2Point[]{g2});
    }

    /**
     * Multi-pairing: compute the product
     * {@code e(P_0, Q_0) * e(P_1, Q_1) * ... * e(P_{n-1}, Q_{n-1})} with a
     * single shared Miller loop and a single final exponentiation. This
     * cuts a 2-pairing verification (e.g. BLS signature verify) to
     * roughly the cost of one pair() call, since the dominant final
     * exponentiation is performed only once.
     * <p>
     * Pairs whose G1 or G2 component is the point at infinity are skipped
     * (their pairing value is 1, identity in GT). If all pairs are skipped,
     * the result is {@link Fp12Element#ONE}.
     *
     * @param g1Points G1 inputs.
     * @param g2Points G2 inputs; must be the same length as {@code g1Points}.
     * @return the product of pairings as an element of GT.
     * @throws IllegalArgumentException if the arrays differ in length.
     */
    public static Fp12Element multiPair(ECPoint[] g1Points, BLS12_381G2Point[] g2Points)
    {
        if (g1Points.length != g2Points.length)
        {
            throw new IllegalArgumentException("g1 / g2 arrays must be the same length");
        }

        // Skip pairs with a point at infinity: their pairing value is 1.
        int n = 0;
        for (int i = 0; i < g1Points.length; ++i)
        {
            if (!g1Points[i].isInfinity() && !g2Points[i].isInfinity())
            {
                n++;
            }
        }
        if (n == 0)
        {
            return Fp12Element.ONE;
        }

        int[][] negXP = new int[n][Fp.SIZE];
        int[][] yP = new int[n][Fp.SIZE];
        Fp2Element[] xQ = new Fp2Element[n];
        Fp2Element[] yQ = new Fp2Element[n];
        Fp2Element[][] t = new Fp2Element[n][];

        int k = 0;
        for (int i = 0; i < g1Points.length; ++i)
        {
            if (g1Points[i].isInfinity() || g2Points[i].isInfinity())
            {
                continue;
            }
            ECPoint normalised = g1Points[i].normalize();
            Fp.fromBigInteger(normalised.getAffineXCoord().toBigInteger().negate(), negXP[k], 0);
            Fp.fromBigInteger(normalised.getAffineYCoord().toBigInteger(), yP[k], 0);
            xQ[k] = g2Points[i].x();
            yQ[k] = g2Points[i].y();
            t[k] = new Fp2Element[]{ xQ[k], yQ[k], Fp2Element.ONE };
            k++;
        }

        Fp12Element f = Fp12Element.ONE;
        int hiBit = ABS_X.bitLength() - 1;
        for (int i = hiBit - 1; i >= 0; --i)
        {
            f = f.square();
            for (int j = 0; j < n; ++j)
            {
                f = doublingStep(f, t[j], negXP[j], yP[j]);
            }
            if (ABS_X.testBit(i))
            {
                for (int j = 0; j < n; ++j)
                {
                    f = additionStep(f, t[j], xQ[j], yQ[j], negXP[j], yP[j]);
                }
            }
        }

        return finalExponentiation(f.conjugate());
    }

    /**
     * Frobenius-based final exponentiation in two stages, producing exactly
     * {@code f^((p^12 - 1) / r)} — the canonical pairing value, with no
     * cube factor.
     * <p>
     * <b>Easy part</b> {@code f^((p^6 - 1)(p^2 + 1))}: computed as
     * {@code conjugate(f) * inverse(f)} (one Fp&sup12; inverse) followed by
     * {@code result * frobeniusSquared(result)} (one Frobenius&sup2; +
     * one mul). After the easy part, the result lives in the cyclotomic
     * subgroup of Fp&sup12;, where {@code conjugate} equals inversion.
     * <p>
     * <b>Hard part</b> {@code easy^((p^4 - p^2 + 1) / r)} via the
     * Hayashida-Hayasaka-Teruya 2020 decomposition for the BLS12 family
     * with k = 12, rearranged to factor out the +3 term that would
     * otherwise leave a cube factor:
     * <pre>
     *   3 * Phi_12(p) / r = (x - 1)^2 * (x + p) * (x^2 + p^2 - 1) + 3
     *   =>  hard          = [(x - 1)^2 / 3] * (x + p) * (x^2 + p^2 - 1) + 1
     * </pre>
     * For the BLS12 family, {@code (x - 1)^2} is divisible by 3 by
     * construction (the curve parameterisation requires it for
     * {@code p(x)} to have integer coefficients), so the {@code /3}
     * collapses into a precomputable ~126-bit integer, applied as a power
     * by {@link #ONE_MINUS_X_OVER_3} followed by one by {@code |x| + 1}.
     * The remaining structure is the same as before, but the final
     * {@code +3} becomes {@code +1}, so we multiply by {@code f} rather
     * than {@code f^3}. Net cost is slightly higher than the cube-factored
     * variant (a ~126-bit power replaces three exp-by-|x| ops + a square)
     * but produces a pairing value byte-comparable against any other
     * BLS12-381 implementation (blst, mcl, zkcrypto, …).
     */
    private static Fp12Element finalExponentiation(Fp12Element f)
    {
        Fp12Element f1 = f.conjugate().mul(f.inverse());            // f^(p^6 - 1)
        Fp12Element easy = f1.frobeniusSquared().mul(f1);            // f^((p^6 - 1)(p^2 + 1))
        return hardPart(easy);
    }

    /**
     * The hard part of the final exponentiation, exposed for cross-package
     * layered testing (the test classes live in
     * {@code org.bouncycastle.crypto.hash2curve.test} and need direct access
     * to the easy/hard split for KAT comparison against reference outputs).
     * Not part of the intended public API of this class — production callers
     * should use {@link #pair} / {@link #multiPair}.
     * <p>
     * {@code f} must lie in the cyclotomic subgroup, as the output of the easy
     * part does: every power here squares with the Granger-Scott or the
     * compressed Karabina squaring of {@code Fp12Element}, both wrong outside it.
     */
    public static Fp12Element hardPart(Fp12Element f)
    {
        // g0 = f^((x - 1)^2 / 3) = h^(|x| + 1) with h = f^((1 - x) / 3). This
        // is the only step that differs from the 3*hard variant; it replaces
        // f^((x - 1)^2) and absorbs the /3. The 63-bit (1 - x) / 3 is dense
        // (28 set bits), so h uses the Granger-Scott power over a width-4 NAF;
        // the power by the sparse |x| uses compressed squaring like expByX.
        Fp12Element h = f.cyclotomicPow(ONE_MINUS_X_OVER_3);
        Fp12Element g0 = h.cyclotomicPowCompressed(ABS_X).mul(h);

        // g1 = g0^(x + p) = g0^x * g0^p.
        Fp12Element g1 = expByX(g0).mul(g0.frobenius());

        // g2 = g1^(x^2 + p^2 - 1) = g1^(x^2) * g1^(p^2) * g1^(-1).
        Fp12Element g1XSq = expByX(expByX(g1));
        Fp12Element g2 = g1XSq.mul(g1.frobeniusSquared()).mul(g1.conjugate());

        // result = g2 * f (the +1 term, vs +3 -> f^3 in the cube-factor variant).
        return g2.mul(f);
    }

    /**
     * In the cyclotomic subgroup of Fp&sup12;, inversion is conjugation. So
     * {@code f^x = f^(-|x|) = conjugate(f^|x|)} for our negative parameter x.
     * The power uses Karabina's compressed squaring.
     */
    private static Fp12Element expByX(Fp12Element f)
    {
        return f.cyclotomicPowCompressed(ABS_X).conjugate();
    }

    /**
     * Doubles {@code T = (X, Y, Z)} in place and returns {@code f} times the
     * tangent line at {@code T} evaluated at {@code P = (xP, yP)}. T is in
     * homogeneous projective coordinates ({@code x = X/Z}, {@code y = Y/Z}),
     * where the doubling and its line cost 3 Fp&sup2; multiplications and 6
     * squarings (Costello, Lange and Naehrig, "Faster pairing computations on
     * curves with high-degree twists", PKC 2010, as written out by Aranha et
     * al., ePrint 2010/354, sec. 4), against 5 and 6 in Jacobian coordinates.
     * <p>
     * On the twist {@code y^2 = x^3 + b'}, {@code b' = 4(1 + I)}, the doubled
     * point is {@code X3 = XY/2 (Y^2 - 9b'Z^2)},
     * {@code Y3 = ((Y^2 + 9b'Z^2)/2)^2 - 27b'^2 Z^4}, {@code Z3 = 2Y^3 Z}, here
     * all multiplied by 4 to avoid the halvings. The tangent has slope
     * {@code 3x^2 / 2y}; after untwisting and multiplying by {@code w^3} its
     * value at {@code P} is {@code (lambda*x - y) - lambda*xP*v + yP*v*w}.
     * Scaled by {@code 2YZ} and reduced with the curve equation
     * {@code Y^2 Z = X^3 + b'Z^3}, the three coefficients are
     * {@code Y^2 - 3b'Z^2}, {@code -3X^2*xP} and {@code 2YZ*yP}. Any Fp&sup2;
     * factor on a line is removed by the final exponentiation.
     */
    private static Fp12Element doublingStep(Fp12Element f, Fp2Element[] t, int[] negXP, int[] yP)
    {
        Fp2Element x1 = t[0], y1 = t[1], z1 = t[2];
        if (y1.isZero())
        {
            throw new ArithmeticException("Miller loop doubled a point of order 2: G2 input not in the subgroup");
        }
        Fp2Element b = y1.square();
        Fp2Element c = z1.square();
        Fp2Element e = c.add(c).add(c).mulByNonResidue();
        e = e.add(e);
        e = e.add(e);                                       // 3b'Z^2
        Fp2Element f3 = e.add(e).add(e);                    // 9b'Z^2
        Fp2Element h = y1.add(z1).square().sub(b).sub(c);   // 2YZ
        Fp2Element j = x1.square();
        Fp2Element ee = e.square();
        Fp2Element xy = x1.mul(y1);

        Fp2Element x3 = xy.add(xy).mul(b.sub(f3));
        Fp2Element ee12 = ee.add(ee).add(ee);
        ee12 = ee12.add(ee12);
        ee12 = ee12.add(ee12);
        Fp2Element y3 = b.add(f3).square().sub(ee12);
        Fp2Element z3 = b.mul(h);
        z3 = z3.add(z3);
        z3 = z3.add(z3);

        Fp2Element l0 = b.sub(e);
        Fp2Element l1 = j.add(j).add(j).mulFp(negXP);
        Fp2Element l4 = h.mulFp(yP);

        t[0] = x3;
        t[1] = y3;
        t[2] = z3;
        return f.mulBy014(l0, l1, l4);
    }

    /**
     * Adds the affine {@code Q = (xQ, yQ)} to {@code T = (X, Y, Z)} in place
     * (homogeneous projective, mixed) and returns {@code f} times the line
     * through {@code T} and {@code Q} evaluated at {@code P}.
     * <p>
     * With {@code theta = Y - yQ*Z}, {@code lambda = X - xQ*Z}, so that the
     * slope is {@code theta / lambda}, the sum is {@code X3 = lambda*H},
     * {@code Y3 = theta*(G - H) - E*Y}, {@code Z3 = Z*E}, where
     * {@code E = lambda^3}, {@code G = X*lambda^2} and
     * {@code H = E + Z*theta^2 - 2G}. The untwisted line, multiplied by
     * {@code w^3}, is {@code (slope*xQ - yQ) - slope*xP*v + yP*v*w}; scaled by
     * {@code lambda} its coefficients are {@code theta*xQ - lambda*yQ},
     * {@code -theta*xP} and {@code lambda*yP}.
     */
    private static Fp12Element additionStep(Fp12Element f, Fp2Element[] t, Fp2Element xQ, Fp2Element yQ,
        int[] negXP, int[] yP)
    {
        Fp2Element x1 = t[0], y1 = t[1], z1 = t[2];
        Fp2Element theta = y1.sub(yQ.mul(z1));
        Fp2Element lambda = x1.sub(xQ.mul(z1));
        if (lambda.isZero())
        {
            // T = +-Q: impossible for Q of prime order r, since T = [k]Q with 1 < k < r.
            throw new ArithmeticException("Miller loop reached T = +-Q: G2 input not in the subgroup");
        }
        Fp2Element c = theta.square();
        Fp2Element d = lambda.square();
        Fp2Element e = lambda.mul(d);
        Fp2Element g = x1.mul(d);
        Fp2Element h = e.add(z1.mul(c)).sub(g.add(g));

        Fp2Element x3 = lambda.mul(h);
        Fp2Element y3 = theta.mul(g.sub(h)).sub(e.mul(y1));
        Fp2Element z3 = z1.mul(e);

        Fp2Element l0 = theta.mul(xQ).sub(lambda.mul(yQ));
        Fp2Element l1 = theta.mulFp(negXP);
        Fp2Element l4 = lambda.mulFp(yP);

        t[0] = x3;
        t[1] = y3;
        t[2] = z3;
        return f.mulBy014(l0, l1, l4);
    }
}
