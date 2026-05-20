package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Optimal ate pairing on BLS12-381: a bilinear, non-degenerate map
 * {@code e: G1 x G2 -> GT} where GT is the order-r subgroup of Fp^12 ^*.
 * <p>
 * This implementation favours obvious correctness over performance:
 * <ul>
 *   <li>G2 is lifted into {@code E(Fp^12)} via the D-twist isomorphism
 *       {@code (x', y') -> (x'/w^2, y'/w^3)}.</li>
 *   <li>The Miller loop runs the textbook affine doubling / addition
 *       formulas on {@code E(Fp^12)} and computes the line evaluations as
 *       full (non-sparse) Fp^12 elements.</li>
 *   <li>The final exponentiation is performed as a single Fp^12 modPow with
 *       exponent {@code (p^12 - 1) / r}, sidestepping the
 *       Frobenius-coefficient infrastructure that the spec-recommended
 *       easy/hard-part split would need.</li>
 * </ul>
 * Sparse line evaluation, Frobenius-based final exponentiation, and a
 * Jacobian-coord G2 in pairing context are all natural follow-on
 * optimisations that preserve the public surface here.
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
     * shorter exponent for {@link Fp12Element#modPow}.
     */
    public static final BigInteger HARD_EXPONENT = Fp2Element.P.pow(4)
        .subtract(Fp2Element.P.pow(2))
        .add(BigInteger.ONE)
        .divide(BLS12_381G1.ORDER);

    /** BLS12-381 trace parameter x = -{@link #ABS_X}. */
    private static final BigInteger X = ABS_X.negate();

    /**
     * {@code (x - 1)^2 / 3}, ~126 bits, used by the cube-factor-free hard
     * part. The division is exact for the BLS12 family by construction.
     */
    private static final BigInteger X_MINUS_1_SQ_OVER_3;

    static
    {
        BigInteger xMinus1Sq = X.subtract(BigInteger.ONE).pow(2);
        BigInteger[] divRem = xMinus1Sq.divideAndRemainder(BigInteger.valueOf(3));
        if (divRem[1].signum() != 0)
        {
            throw new IllegalStateException("(x - 1)^2 must be divisible by 3 for BLS12 family");
        }
        X_MINUS_1_SQ_OVER_3 = divRem[0];
    }

    /** Fp^12 lift of the constant 2, hoisted out of the Miller loop. */
    private static final Fp12Element TWO;

    /** Fp^12 lift of the constant 3, hoisted out of the Miller loop. */
    private static final Fp12Element THREE;

    /** {@code w^{-2}} in Fp^12, used to lift G2 via the D-twist. */
    private static final Fp12Element W_INV_SQUARED;

    /** {@code w^{-3}} in Fp^12, used to lift G2 via the D-twist. */
    private static final Fp12Element W_INV_CUBED;

    static
    {
        // (1 - I) / 2 in Fp^2: numerator components are (1, -1), divided by 2.
        BigInteger half = BigInteger.valueOf(2).modInverse(Fp2Element.P);
        Fp2Element oneMinusIOverTwo = Fp2Element.of(half, Fp2Element.P.subtract(half));

        // w^-2 = 1/v in Fp^6 = v^2 / xi where xi = 1 + I.
        // v^2 has Fp^6 representation (0, 0, 1) so w^-2 = (0, 0, (1-I)/2) in Fp^6.
        W_INV_SQUARED = Fp12Element.fromFp6(Fp6Element.of(
            Fp2Element.ZERO, Fp2Element.ZERO, oneMinusIOverTwo));

        // w^-3 = w * w^-4 = w * v^-2. v^-2 has Fp^6 representation (0, (1-I)/2, 0).
        // In Fp^12 = Fp^6 + Fp^6 * w, w^-3 has c0 = 0, c1 = v^-2.
        W_INV_CUBED = Fp12Element.of(Fp6Element.ZERO, Fp6Element.of(
            Fp2Element.ZERO, oneMinusIOverTwo, Fp2Element.ZERO));

        TWO = liftFp(BigInteger.valueOf(2));
        THREE = liftFp(BigInteger.valueOf(3));
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

        // Filter out infinities and lift to Fp^12 once up front.
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

        Fp12Element[] xP = new Fp12Element[n];
        Fp12Element[] yP = new Fp12Element[n];
        Fp12Element[] xT = new Fp12Element[n];
        Fp12Element[] yT = new Fp12Element[n];
        Fp12Element[] xQ = new Fp12Element[n];
        Fp12Element[] yQ = new Fp12Element[n];

        int k = 0;
        for (int i = 0; i < g1Points.length; ++i)
        {
            if (g1Points[i].isInfinity() || g2Points[i].isInfinity())
            {
                continue;
            }
            ECPoint normalised = g1Points[i].normalize();
            xP[k] = liftFp(normalised.getAffineXCoord().toBigInteger());
            yP[k] = liftFp(normalised.getAffineYCoord().toBigInteger());

            Fp12Element qx = liftFp2(g2Points[i].x()).mul(W_INV_SQUARED);
            Fp12Element qy = liftFp2(g2Points[i].y()).mul(W_INV_CUBED);
            xQ[k] = qx;
            yQ[k] = qy;
            xT[k] = qx;
            yT[k] = qy;
            k++;
        }

        Fp12Element f = Fp12Element.ONE;
        int hiBit = ABS_X.bitLength() - 1;
        for (int i = hiBit - 1; i >= 0; --i)
        {
            f = f.square();
            for (int j = 0; j < n; ++j)
            {
                Fp12Element[] doubled = doubleAndLine(xT[j], yT[j], xP[j], yP[j]);
                xT[j] = doubled[0];
                yT[j] = doubled[1];
                f = f.mul(doubled[2]);
            }
            if (ABS_X.testBit(i))
            {
                for (int j = 0; j < n; ++j)
                {
                    Fp12Element[] added = addAndLine(xT[j], yT[j], xQ[j], yQ[j], xP[j], yP[j]);
                    xT[j] = added[0];
                    yT[j] = added[1];
                    f = f.mul(added[2]);
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
     * collapses into a precomputable ~126-bit integer that is applied
     * via a single {@link Fp12Element#modPow} on {@link #X_MINUS_1_SQ_OVER_3}.
     * The remaining structure is the same as before, but the final
     * {@code +3} becomes {@code +1}, so we multiply by {@code f} rather
     * than {@code f^3}. Net cost is slightly higher than the cube-factored
     * variant (~126-bit modPow replaces three exp-by-|x| ops + a square)
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
     */
    public static Fp12Element hardPart(Fp12Element f)
    {
        // g0 = f^((x - 1)^2 / 3), via a direct ~126-bit modPow. This is
        // the only step that differs from the 3*hard variant; it replaces
        // f^((x - 1)^2) and absorbs the /3.
        Fp12Element g0 = f.modPow(X_MINUS_1_SQ_OVER_3);

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
     */
    private static Fp12Element expByX(Fp12Element f)
    {
        return f.modPow(ABS_X).conjugate();
    }

    /**
     * Affine doubling of {@code T = (xT, yT)} with line evaluation at
     * {@code P = (xP, yP)}. All coordinates are in Fp^12.
     *
     * @return {@code {x_2T, y_2T, line_T(P)}}.
     */
    private static Fp12Element[] doubleAndLine(Fp12Element xT, Fp12Element yT,
        Fp12Element xP, Fp12Element yP)
    {
        // slope lambda = 3 * xT^2 / (2 * yT) since the curve has A = 0.
        Fp12Element lambda = xT.square().mul(THREE).mul(TWO.mul(yT).inverse());
        Fp12Element xNew = lambda.square().sub(xT).sub(xT);
        Fp12Element yNew = lambda.mul(xT.sub(xNew)).sub(yT);
        // line(X, Y) = Y - yT - lambda * (X - xT)
        Fp12Element line = yP.sub(yT).sub(lambda.mul(xP.sub(xT)));
        return new Fp12Element[]{xNew, yNew, line};
    }

    /**
     * Affine addition of {@code T = (xT, yT)} and {@code Q = (xQ, yQ)} with
     * line evaluation at {@code P = (xP, yP)}.
     *
     * @return {@code {x_T+Q, y_T+Q, line_TQ(P)}}.
     */
    private static Fp12Element[] addAndLine(Fp12Element xT, Fp12Element yT,
        Fp12Element xQ, Fp12Element yQ, Fp12Element xP, Fp12Element yP)
    {
        Fp12Element lambda = yQ.sub(yT).mul(xQ.sub(xT).inverse());
        Fp12Element xNew = lambda.square().sub(xT).sub(xQ);
        Fp12Element yNew = lambda.mul(xT.sub(xNew)).sub(yT);
        Fp12Element line = yP.sub(yT).sub(lambda.mul(xP.sub(xT)));
        return new Fp12Element[]{xNew, yNew, line};
    }

    private static Fp12Element liftFp(BigInteger v)
    {
        return Fp12Element.fromFp6(Fp6Element.fromFp2(Fp2Element.fromFp(v)));
    }

    private static Fp12Element liftFp2(Fp2Element v)
    {
        return Fp12Element.fromFp6(Fp6Element.fromFp2(v));
    }
}
