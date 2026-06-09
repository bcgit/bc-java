package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Fast subgroup-membership tests for BLS12-381 G1 and G2, replacing the
 * naive {@code [r] * P == 0} scalar multiplication (255-bit).
 * <p>
 * For G1: the GLV endomorphism &sigma;(x, y) = (&beta;&middot;x, y), where
 * &beta; is a primitive cube root of unity in Fp, has eigenvalue
 * &lambda; = x&sup2; - 1 on G1 (a primitive cube root of unity in Z/r). The
 * test {@code σ(P) == [λ] P} reduces the scalar to ~128 bits.
 * <p>
 * For G2: the untwist-Frobenius-twist endomorphism &psi; has eigenvalue
 * x (the BLS parameter) on G2. The test {@code ψ(P) == [x] P} reduces
 * the scalar to ~64 bits, and &psi; itself is essentially free
 * (one Fp&sup2; conjugation + one Fp&sup2; multiplication per coordinate).
 * <p>
 * Both checks assume the input is already on the corresponding curve;
 * verifying the curve equation is the caller's responsibility (and is done
 * implicitly by {@link BLS12_381G2Point#of} for G2 and {@link ECPoint#isValid}
 * for G1).
 */
public class BLS12_381SubgroupCheck
{
    /** BLS12-381 trace parameter x: -0xd201000000010000. */
    private static final BigInteger X = new BigInteger("-d201000000010000", 16);

    /**
     * Eigenvalue of &sigma; on G1: a primitive cube root of unity in Z/r.
     * The two candidates are {@code x² - 1} and its square (which equals
     * {@code -x² mod r}); the static initialiser picks whichever
     * matches our chosen &sigma; direction by probing on the canonical
     * generator.
     */
    private static final BigInteger LAMBDA_G1;

    /**
     * Primitive cube root of unity in Fp: &beta; satisfies
     * &beta;&sup2; + &beta; + 1 &equiv; 0 (mod p). Derived as
     * {@code (-1 + sqrt(-3))/2} in Fp; the static initialiser sanity-checks
     * &beta;&sup2; + &beta; + 1 &equiv; 0.
     */
    private static final BigInteger BETA;

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
        BETA = beta;

        Fp2Element nonResidue = Fp2Element.of(1, 1);
        PSI_X = nonResidue.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(3))).inverse();
        PSI_Y = nonResidue.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))).inverse();

        // Probe the eigenvalue of σ on G1 by checking which cube root of
        // unity matches σ(G1).
        BigInteger r = BLS12_381G1.ORDER;
        BigInteger candidate1 = X.multiply(X).subtract(BigInteger.ONE).mod(r);
        BigInteger candidate2 = candidate1.multiply(candidate1).mod(r);
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        ECPoint sigmaG = applySigmaWithBeta(g, BETA);
        ECPoint test1 = g.multiply(candidate1).normalize();
        LAMBDA_G1 = sigmaG.equals(test1) ? candidate1 : candidate2;
    }

    private static ECPoint applySigmaWithBeta(ECPoint p, BigInteger beta)
    {
        ECPoint normalised = p.normalize();
        BigInteger x = normalised.getAffineXCoord().toBigInteger();
        BigInteger y = normalised.getAffineYCoord().toBigInteger();
        BigInteger xBeta = x.multiply(beta).mod(Fp2Element.P);
        return normalised.getCurve().createPoint(xBeta, y);
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
     * Returns {@code true} iff {@code σ(P) == [x² - 1] P}, which is
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
        ECPoint sigmaP = sigmaG1(p);
        ECPoint lambdaP = p.multiply(LAMBDA_G1).normalize();
        return sigmaP.equals(lambdaP);
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
