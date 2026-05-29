package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;
import java.security.SecureRandom;


/**
 * Level-independent SQIsign keygen driver. Java mirror of
 * {@code protocols_keygen} from {@code src/signature/ref/lvlx/keygen.c}.
 *
 * <p>Driven from {@link SQIsignKeyGenLvl1}, {@link SQIsignKeyGenLvl3},
 * {@link SQIsignKeyGenLvl5}, each of which supplies the level-specific
 * precomp constants and the two dispatching functional callbacks for
 * {@code arbitrary_isogeny_evaluation} and {@code ec_curve_to_basis_2f_to_hint}.</p>
 */
final class SQIsignKeyGen
{
    private SQIsignKeyGen()
    {
    }

    /** Step 3 dispatch: ideal → isogeny + canonical basis on the codomain. */
    interface IdealToIsogeny
    {
        int arbitraryIsogenyEvaluation(EcBasis canonicalBasis, EcCurve codomain,
                                       QuatLeftIdeal lideal, SecureRandom random);
    }

    /** Step 4 dispatch: deterministic canonical 2-power basis with hint. */
    interface ToHint
    {
        int toHint(EcBasis basis, EcCurve curve, int torsionEvenPower);
    }

    static int sampleSecretIdeal(QuatLeftIdeal lideal,
                                 Ibz ibzSecDegree,
                                 QuatRepresentIntegerParams representParams,
                                 SecureRandom random)
    {
        return Normeq.samplingRandomIdealO0GivenNorm(
            lideal, ibzSecDegree, /* isPrime = */ true,
            representParams, /* primeCofactor = */ null, random);
    }

    static int reduceToPrimeNormEquivalent(QuatLeftIdeal lideal,
                                           QuatAlg quatalgPinfty,
                                           int primalityNumIter,
                                           int equivBoundCoeff,
                                           SecureRandom random)
    {
        return LllApplications.primeNormReducedEquivalent(
            lideal, quatalgPinfty, primalityNumIter, equivBoundCoeff, random);
    }

    /** Raw output of {@link #protocolsKeygenFull}: each level wrapper boxes
     *  this into its own LvlN.KeyPair before returning to callers. */
    static final class Result
    {
        final SQIsignSecretKeyData sk;
        final int hintPk;

        Result(SQIsignSecretKeyData sk, int hintPk)
        {
            this.sk = sk;
            this.hintPk = hintPk;
        }
    }

    static Result protocolsKeygenFull(
        Ibz ibzSecDegree,
        QuatRepresentIntegerParams representParams,
        QuatAlg quatalgPinfty,
        int primalityNumIter,
        int equivBoundCoeff,
        int torsionEvenPower,
        long pCofactorFor2f,
        IdealToIsogeny idealToIsogeny,
        ToHint toHint,
        SecureRandom random)
    {
        SQIsignSecretKeyData sk = new SQIsignSecretKeyData();
        EcBasis B0Two = new EcBasis();

        int found = 0;
        QuatLeftIdeal lideal = sk.secretIdeal;
        while (found == 0)
        {
            int sampled = sampleSecretIdeal(lideal, ibzSecDegree, representParams, random);
            int reduced = sampled == 1
                ? reduceToPrimeNormEquivalent(lideal, quatalgPinfty, primalityNumIter, equivBoundCoeff, random)
                : 0;
            if (sampled != 1 || reduced != 1)
            {
                continue;
            }
            found = idealToIsogeny.arbitraryIsogenyEvaluation(B0Two, sk.curve, lideal, random);
        }

        int hintPk = toHint.toHint(sk.canonicalBasis, sk.curve, torsionEvenPower);

        BigInteger[][] mat = EcDlog.changeOfBasisMatrixTate(
            sk.canonicalBasis, B0Two, sk.curve,
            torsionEvenPower, torsionEvenPower, pCofactorFor2f);
        if (mat == null)
        {
            throw new IllegalStateException("change_of_basis_matrix_tate: dlog failed");
        }
        Ibz.set(sk.matBAcanToBA0Two[0][0], 0);
        sk.matBAcanToBA0Two[0][0].v = mat[0][0];
        sk.matBAcanToBA0Two[0][1].v = mat[0][1];
        sk.matBAcanToBA0Two[1][0].v = mat[1][0];
        sk.matBAcanToBA0Two[1][1].v = mat[1][1];

        return new Result(sk, hintPk);
    }
}
