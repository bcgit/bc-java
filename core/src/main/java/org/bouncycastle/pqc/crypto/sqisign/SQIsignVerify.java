package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Level-independent SQIsign verification. Java mirror of
 * {@code src/verification/ref/lvlx/verify.c}.
 *
 * <p>Driven from {@link SQIsignVerifyLvl1}, {@link SQIsignVerifyLvl3},
 * {@link SQIsignVerifyLvl5}, each of which supplies the level-specific
 * precomp constants and four functional callbacks for {@code fromHint},
 * {@code chainComputeAndEvalVerify}, and {@code hashToChallenge}.</p>
 */
final class SQIsignVerify
{
    private SQIsignVerify()
    {
    }

    interface FromHint
    {
        int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint);
    }

    interface ChainComputeAndEvalVerify
    {
        int chainComputeAndEvalVerify(int n, ThetaCoupleCurve E12,
                                      ThetaKernelCouplePoints ker, boolean extraTorsion,
                                      ThetaCoupleCurve E34,
                                      org.bouncycastle.pqc.crypto.sqisign.ThetaCouplePoint[] P12,
                                      int numP);
    }

    interface HashToChallenge
    {
        BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message);
    }

    static int checkCanonicalBasisChangeMatrix(SQIsignSignature sig,
                                               int sqisignResponseLength, int hdExtraTorsion)
    {
        int bits = sqisignResponseLength + hdExtraTorsion - sig.backtracking;
        if (bits < 0)
        {
            return 0;
        }
        BigInteger aux = BigInteger.ONE.shiftLeft(bits);
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                if (aux.compareTo(sig.matBchallCanToBChall[i][j]) <= 0)
                {
                    return 0;
                }
            }
        }
        return 1;
    }

    static int computeChallengeVerify(EcCurve eChall, SQIsignSignature sig,
                                      EcCurve ePk, int hintPk,
                                      int torsionEvenPower, FromHint fromHint)
    {
        EcCurve domain = new EcCurve();
        EcCurve.copy(domain, ePk);
        EcOps.normalizeCurveAndA24(domain);

        EcBasis basEA = new EcBasis();
        if (fromHint.fromHint(basEA, domain, torsionEvenPower, hintPk) != 1)
        {
            return 0;
        }

        EcIsogEven phiChall = new EcIsogEven();
        EcCurve.copy(phiChall.curve, domain);
        phiChall.length = torsionEvenPower - sig.backtracking;

        if (EcLadder.ladder3pt(phiChall.kernel,
            sig.challCoeff, torsionEvenPower,
            basEA.P, basEA.Q, basEA.PmQ, domain) != 1)
        {
            return 0;
        }

        if (sig.backtracking > 0)
        {
            EcLadder.dblIter(phiChall.kernel, sig.backtracking, phiChall.kernel, domain);
        }

        EcCurve.copy(eChall, phiChall.curve);
        int evalRet = EcIsogChains.evalEven(eChall, phiChall, null, 0);
        return evalRet == 0 ? 1 : 0;
    }

    static int matrixScalarApplicationEvenBasis(EcBasis bas, EcCurve E,
                                                BigInteger[][] mat, int f)
    {
        EcBasis tmp = new EcBasis();
        EcBasis.copy(tmp, bas);

        if (EcBiLadder.biscalarMul(bas.P, mat[0][0], mat[1][0], f, tmp, E) != 1)
        {
            return 0;
        }
        if (EcBiLadder.biscalarMul(bas.Q, mat[0][1], mat[1][1], f, tmp, E) != 1)
        {
            return 0;
        }
        BigInteger powTwo = BigInteger.ONE.shiftLeft(f);
        BigInteger s0 = mat[0][0].subtract(mat[0][1]).mod(powTwo);
        BigInteger s1 = mat[1][0].subtract(mat[1][1]).mod(powTwo);
        return EcBiLadder.biscalarMul(bas.PmQ, s0, s1, f, tmp, E);
    }

    static int challengeAndAuxBasisVerify(EcBasis bChallCan, EcBasis bAuxCan,
                                          EcCurve eChall, EcCurve eAux,
                                          SQIsignSignature sig,
                                          int powDim2DegResp,
                                          int torsionEvenPower, int hdExtraTorsion,
                                          FromHint fromHint)
    {
        if (fromHint.fromHint(bChallCan, eChall, torsionEvenPower, sig.hintChall) != 1)
        {
            return 0;
        }
        int dblIters1 = torsionEvenPower - powDim2DegResp - hdExtraTorsion - sig.twoRespLength;
        if (dblIters1 > 0)
        {
            EcLadder.dblIterBasis(bChallCan, dblIters1, bChallCan, eChall);
        }

        if (fromHint.fromHint(bAuxCan, eAux, torsionEvenPower, sig.hintAux) != 1)
        {
            return 0;
        }
        int dblIters2 = torsionEvenPower - powDim2DegResp - hdExtraTorsion;
        if (dblIters2 > 0)
        {
            EcLadder.dblIterBasis(bAuxCan, dblIters2, bAuxCan, eAux);
        }

        int f = powDim2DegResp + hdExtraTorsion + sig.twoRespLength;
        return matrixScalarApplicationEvenBasis(bChallCan, eChall, sig.matBchallCanToBChall, f);
    }

    static int twoResponseIsogenyVerify(EcCurve eChall, EcBasis bChallCan,
                                        SQIsignSignature sig,
                                        int powDim2DegResp, int hdExtraTorsion)
    {
        EcPoint ker = new EcPoint();
        BigInteger m00 = sig.matBchallCanToBChall[0][0];
        BigInteger m10 = sig.matBchallCanToBChall[1][0];
        if (!m00.testBit(0) && !m10.testBit(0))
        {
            EcPoint.copy(ker, bChallCan.Q);
        }
        else
        {
            EcPoint.copy(ker, bChallCan.P);
        }

        EcPoint[] points = new EcPoint[]{
            bChallCan.P.copy(),
            bChallCan.Q.copy(),
            bChallCan.PmQ.copy()
        };

        int dblIters = powDim2DegResp + hdExtraTorsion;
        if (dblIters > 0)
        {
            EcLadder.dblIter(ker, dblIters, ker, eChall);
        }

        int evalRet = EcIsogChains.evalSmallChain(eChall, ker, sig.twoRespLength,
            points, 3, false);
        if (evalRet != 0)
        {
            return 0;
        }

        EcPoint.copy(bChallCan.P, points[0]);
        EcPoint.copy(bChallCan.Q, points[1]);
        EcPoint.copy(bChallCan.PmQ, points[2]);
        return 1;
    }

    static int computeCommitmentCurveVerify(EcCurve eCom,
                                            EcBasis bChallCan, EcBasis bAuxCan,
                                            EcCurve eChall, EcCurve eAux,
                                            int powDim2DegResp,
                                            ChainComputeAndEvalVerify chainVerify)
    {
        ThetaCoupleCurve EchallEaux = new ThetaCoupleCurve();
        EcCurve.copy(EchallEaux.E1, eChall);
        EcCurve.copy(EchallEaux.E2, eAux);

        ThetaKernelCouplePoints dimTwoKer = new ThetaKernelCouplePoints();
        HdOps.copyBasesToKernel(dimTwoKer, bChallCan, bAuxCan);

        ThetaCoupleCurve codomain = new ThetaCoupleCurve();
        EcOps.curveInit(codomain.E1);
        EcOps.curveInit(codomain.E2);

        int codomainSplits;
        if (powDim2DegResp == 0)
        {
            codomainSplits = 1;
            EcCurve.copy(codomain.E1, EchallEaux.E1);
            EcCurve.copy(codomain.E2, EchallEaux.E2);
            if (EcOps.isBasisFourTorsion(bChallCan, eChall) == 0)
            {
                return 0;
            }
        }
        else
        {
            codomainSplits = chainVerify.chainComputeAndEvalVerify(
                powDim2DegResp, EchallEaux, dimTwoKer,
                /* extraTorsion = */ true,
                codomain, /* P12 */ null, 0);
        }

        EcCurve.copy(eCom, codomain.E1);
        return codomainSplits;
    }

    static int protocolsVerify(GfField field,
                               SQIsignSignature sig,
                               EcCurve pkCurve, int hintPk,
                               byte[] message,
                               int torsionEvenPower, int sqisignResponseLength,
                               int hdExtraTorsion,
                               FromHint fromHint,
                               ChainComputeAndEvalVerify chainVerify,
                               HashToChallenge hashToChallenge)
    {
        if (checkCanonicalBasisChangeMatrix(sig, sqisignResponseLength, hdExtraTorsion) != 1)
        {
            return 0;
        }

        int powDim2DegResp = sqisignResponseLength - sig.twoRespLength - sig.backtracking;
        if (powDim2DegResp < 0 || powDim2DegResp == 1)
        {
            return 0;
        }

        if (EcOps.curveVerifyA(pkCurve.A) != 1)
        {
            return 0;
        }

        EcCurve eAux = new EcCurve();
        eAux.field = field;
        if (EcOps.curveInitFromA(eAux, sig.eAuxA) != 1)
        {
            return 0;
        }

        EcCurve eChall = new EcCurve();
        eChall.field = field;
        if (computeChallengeVerify(eChall, sig, pkCurve, hintPk,
            torsionEvenPower, fromHint) != 1)
        {
            return 0;
        }

        EcBasis bChallCan = new EcBasis();
        EcBasis bAuxCan = new EcBasis();
        if (challengeAndAuxBasisVerify(bChallCan, bAuxCan, eChall, eAux,
            sig, powDim2DegResp, torsionEvenPower, hdExtraTorsion, fromHint) != 1)
        {
            return 0;
        }

        if (sig.twoRespLength > 0)
        {
            if (twoResponseIsogenyVerify(eChall, bChallCan, sig,
                powDim2DegResp, hdExtraTorsion) != 1)
            {
                return 0;
            }
        }

        EcCurve eCom = new EcCurve();
        eCom.field = field;
        if (computeCommitmentCurveVerify(eCom, bChallCan, bAuxCan,
            eChall, eAux, powDim2DegResp, chainVerify) != 1)
        {
            return 0;
        }

        BigInteger chkChall = hashToChallenge.hashToChallenge(pkCurve, eCom, message);
        return sig.challCoeff.equals(chkChall) ? 1 : 0;
    }
}
