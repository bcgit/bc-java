package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Fast subgroup-membership tests for BLS12-381 G1 and G2, replacing the
 * naive {@code [r] * P == 0} scalar multiplication (255-bit).
 * <p>
 * For G1: the GLV endomorphism &sigma;(x, y) = (&beta;&middot;x, y), where
 * &beta; is the primitive cube root of unity in Fp for which &sigma; has
 * eigenvalue -x&sup2; on G1. The test {@code σ(P) == [-x²] P} holds if and
 * only if P has order r (M. Scott, "A note on group membership tests for G1,
 * G2 and GT on BLS pairing-friendly curves", IACR ePrint 2021/1130), and
 * {@code [x²] P} is two multiplications by the 64-bit |x|, which has only six
 * bits set.
 * <p>
 * For G2: the untwist-Frobenius-twist endomorphism &psi; has eigenvalue
 * x (the BLS parameter) on G2. The test {@code ψ(P) == [x] P} reduces
 * the scalar to ~64 bits, and &psi; itself is essentially free
 * (one Fp&sup2; conjugation + one Fp&sup2; multiplication per coordinate).
 * <p>
 * Both checks assume the input is already on the corresponding curve;
 * verifying the curve equation is the caller's responsibility (and is done
 * implicitly by {@link BLS12_381G2Point#of} for G2 and by
 * {@link BLS12_381BasicScheme#keyValidate} for G1).
 */
public class BLS12_381SubgroupCheck
{
    /** BLS12-381 trace parameter x: -0xd201000000010000. */
    private static final BigInteger X = new BigInteger("-d201000000010000", 16);

    /** |x|, the absolute value of the trace parameter. */
    private static final BigInteger ABS_X = X.negate();

    /**
     * Primitive cube root of unity in Fp: &beta; satisfies
     * &beta;&sup2; + &beta; + 1 &equiv; 0 (mod p). Of the two roots,
     * {@code (-1 ± sqrt(-3))/2}, the static initialiser takes the one for
     * which &sigma; acts as {@code [-x²]} on the generator, the direction
     * the G1 test needs, and sanity-checks &beta;&sup2; + &beta; + 1 &equiv; 0.
     */
    private static final BigInteger BETA;

    /** Jacobian coordinates (X, Y, Z) of the point at infinity on G1. */
    private static final BigInteger[] JACOBIAN_INFINITY = { BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO };

    /** &psi; coefficient for G2 x-coordinate: 1 / ((1 + I)^((p - 1) / 3)) in Fp&sup2;. */
    private static final Fp2Element PSI_X;

    /** &psi; coefficient for G2 y-coordinate: 1 / ((1 + I)^((p - 1) / 2)) in Fp&sup2;. */
    private static final Fp2Element PSI_Y;

    static
    {
        BigInteger p = Fp2Element.P;

        // β = (-1 + sqrt(-3)) / 2 in Fp.
        BigInteger negThree = p.subtract(BigInteger.valueOf(3));
        BigInteger sqrtNegThree = negThree.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        if (!sqrtNegThree.multiply(sqrtNegThree).mod(p).equals(negThree))
        {
            throw new IllegalStateException("could not derive sqrt(-3) in Fp");
        }
        BigInteger half = BigInteger.valueOf(2).modInverse(p);
        BigInteger beta = sqrtNegThree.subtract(BigInteger.ONE).multiply(half).mod(p);
        if (beta.multiply(beta).add(beta).add(BigInteger.ONE).mod(p).signum() != 0)
        {
            throw new IllegalStateException("derived beta does not satisfy beta^2 + beta + 1 = 0");
        }
        // The other cube root, beta^2 = -1 - beta, gives sigma^2 with eigenvalue x^2 - 1.
        ECPoint g = BLS12_381G1.getGenerator(BLS12_381G1.createCurve());
        BigInteger gx = g.getAffineXCoord().toBigInteger();
        BigInteger gy = g.getAffineYCoord().toBigInteger();
        if (!sigmaIsMinusXSquared(gx, gy, beta))
        {
            beta = p.subtract(BigInteger.ONE).subtract(beta);
            if (!sigmaIsMinusXSquared(gx, gy, beta))
            {
                throw new IllegalStateException("neither cube root of unity gives sigma = [-x^2] on G1");
            }
        }
        BETA = beta;

        Fp2Element nonResidue = Fp2Element.of(1, 1);
        PSI_X = nonResidue.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(3))).inverse();
        PSI_Y = nonResidue.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))).inverse();
    }

    private BLS12_381SubgroupCheck()
    {
    }

    /**
     * The GLV endomorphism on G1: &sigma;(x, y) = (&beta;&middot;x, y).
     * <p>
     * Exposed for cross-package layered testing (the test classes live in
     * {@code org.bouncycastle.crypto.hash2curve.test} and need direct access
     * to the endomorphism for verification against the naive
     * {@code [r] * P == 0} check). Not part of the intended public API of
     * this class — production callers should use {@link #isInG1Subgroup}.
     */
    public static ECPoint sigmaG1(ECPoint p)
    {
        if (p.isInfinity())
        {
            return p;
        }
        ECPoint normalised = p.normalize();
        BigInteger x = normalised.getAffineXCoord().toBigInteger();
        BigInteger y = normalised.getAffineYCoord().toBigInteger();
        BigInteger xBeta = x.multiply(BETA).mod(Fp2Element.P);
        return normalised.getCurve().createPoint(xBeta, y);
    }

    /**
     * The untwist-Frobenius-twist endomorphism on G2:
     * {@code (x, y) -> (conjugate(x) * PSI_X, conjugate(y) * PSI_Y)}.
     * <p>
     * Exposed for cross-package layered testing (see {@link #sigmaG1} for
     * the rationale). Not part of the intended public API of this class —
     * production callers should use {@link #isInG2Subgroup}.
     */
    public static BLS12_381G2Point psiG2(BLS12_381G2Point p)
    {
        if (p.isInfinity())
        {
            return p;
        }
        return BLS12_381G2Point.ofUnchecked(
            p.x().frobenius().mul(PSI_X),
            p.y().frobenius().mul(PSI_Y));
    }

    /**
     * Test G1 prime-order subgroup membership.
     * <p>
     * Returns {@code true} iff {@code σ(P) == [-x²] P}, which is
     * equivalent to {@code [r] P == 0} for any P on E(Fp).
     */
    public static boolean isInG1Subgroup(ECPoint p)
    {
        if (p == null)
        {
            return false;
        }
        if (p.isInfinity())
        {
            return true;
        }
        ECPoint normalised = p.normalize();
        return sigmaIsMinusXSquared(normalised.getAffineXCoord().toBigInteger(),
            normalised.getAffineYCoord().toBigInteger(), BETA);
    }

    /**
     * {@code (beta * x, y) == -[x²](x, y)} for an affine point (x, y) on E(Fp),
     * with {@code [x²]} computed as two multiplications by |x| in Jacobian
     * coordinates and compared without an inversion: {@code (X, Y, Z)}
     * equals {@code (beta * x, -y)} iff {@code X == beta * x * Z²} and
     * {@code Y == -y * Z³}. The left side is never the point at infinity.
     */
    private static boolean sigmaIsMinusXSquared(BigInteger x, BigInteger y, BigInteger beta)
    {
        BigInteger[] q = jacobianMulAbsX(jacobianMulAbsX(new BigInteger[]{ x, y, BigInteger.ONE }));
        if (q[2].signum() == 0)
        {
            return false;
        }
        BigInteger zz = sqrFp(q[2]);
        return q[0].equals(mulFp(mulFp(beta, x), zz))
            && q[1].equals(Fp2Element.negFp(mulFp(y, mulFp(zz, q[2]))));
    }

    private static BigInteger mulFp(BigInteger a, BigInteger b)
    {
        return Fp2Element.reduce(a.multiply(b));
    }

    private static BigInteger sqrFp(BigInteger a)
    {
        return Fp2Element.reduce(a.multiply(a));
    }

    /** {@code [|x|] P} by left-to-right double-and-add: 63 doublings, 5 additions. */
    private static BigInteger[] jacobianMulAbsX(BigInteger[] p)
    {
        BigInteger[] r = p;
        for (int i = ABS_X.bitLength() - 2; i >= 0; --i)
        {
            r = jacobianDouble(r);
            if (ABS_X.testBit(i))
            {
                r = jacobianAdd(r, p);
            }
        }
        return r;
    }

    /** dbl-2009-l (Explicit-Formulas Database) for a = 0: 2M + 5S. Infinity doubles to infinity. */
    private static BigInteger[] jacobianDouble(BigInteger[] p)
    {
        BigInteger x1 = p[0], y1 = p[1], z1 = p[2];
        BigInteger a = sqrFp(x1);
        BigInteger b = sqrFp(y1);
        BigInteger c = sqrFp(b);
        BigInteger t = Fp2Element.subFp(Fp2Element.subFp(sqrFp(Fp2Element.addFp(x1, b)), a), c);
        BigInteger d = Fp2Element.addFp(t, t);
        BigInteger e = Fp2Element.addFp(Fp2Element.addFp(a, a), a);
        BigInteger x3 = Fp2Element.subFp(sqrFp(e), Fp2Element.addFp(d, d));
        BigInteger c8 = Fp2Element.addFp(c, c);
        c8 = Fp2Element.addFp(c8, c8);
        c8 = Fp2Element.addFp(c8, c8);
        BigInteger y3 = Fp2Element.subFp(mulFp(e, Fp2Element.subFp(d, x3)), c8);
        BigInteger yz = mulFp(y1, z1);
        return new BigInteger[]{ x3, y3, Fp2Element.addFp(yz, yz) };
    }

    /**
     * add-2007-bl (Explicit-Formulas Database): 11M + 5S. Handles either
     * input at infinity and the doubling and inverse cases, which the
     * formula does not.
     */
    private static BigInteger[] jacobianAdd(BigInteger[] p, BigInteger[] q)
    {
        BigInteger x1 = p[0], y1 = p[1], z1 = p[2];
        BigInteger x2 = q[0], y2 = q[1], z2 = q[2];
        if (z1.signum() == 0)
        {
            return q;
        }
        if (z2.signum() == 0)
        {
            return p;
        }
        BigInteger z1z1 = sqrFp(z1);
        BigInteger z2z2 = sqrFp(z2);
        BigInteger u1 = mulFp(x1, z2z2);
        BigInteger u2 = mulFp(x2, z1z1);
        BigInteger s1 = mulFp(mulFp(y1, z2), z2z2);
        BigInteger s2 = mulFp(mulFp(y2, z1), z1z1);
        BigInteger h = Fp2Element.subFp(u2, u1);
        BigInteger sy = Fp2Element.subFp(s2, s1);
        if (h.signum() == 0)
        {
            // Same x: P + P is a doubling, P + (-P) is infinity.
            return sy.signum() == 0 ? jacobianDouble(p) : JACOBIAN_INFINITY;
        }
        BigInteger h2 = Fp2Element.addFp(h, h);
        BigInteger i = sqrFp(h2);
        BigInteger j = mulFp(h, i);
        BigInteger r = Fp2Element.addFp(sy, sy);
        BigInteger v = mulFp(u1, i);
        BigInteger x3 = Fp2Element.subFp(Fp2Element.subFp(sqrFp(r), j), Fp2Element.addFp(v, v));
        BigInteger s1j = mulFp(s1, j);
        BigInteger y3 = Fp2Element.subFp(mulFp(r, Fp2Element.subFp(v, x3)), Fp2Element.addFp(s1j, s1j));
        BigInteger zs = sqrFp(Fp2Element.addFp(z1, z2));
        BigInteger z3 = mulFp(Fp2Element.subFp(Fp2Element.subFp(zs, z1z1), z2z2), h);
        return new BigInteger[]{ x3, y3, z3 };
    }

    /**
     * Test G2 prime-order subgroup membership.
     * <p>
     * Returns {@code true} iff {@code ψ(P) == [x] P}, which is
     * equivalent to {@code [r] P == 0} for any P on E'(Fp&sup2;).
     */
    public static boolean isInG2Subgroup(BLS12_381G2Point p)
    {
        if (p == null)
        {
            return false;
        }
        if (p.isInfinity())
        {
            return true;
        }
        return psiG2(p).equals(p.multiply(X));
    }
}
