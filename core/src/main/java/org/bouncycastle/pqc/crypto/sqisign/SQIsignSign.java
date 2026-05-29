package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;
import java.security.SecureRandom;


/**
 * Level-independent SQIsign signing driver. Java mirror of
 * {@code src/signature/ref/lvlx/sign.c}.
 *
 * <p>Driven from {@link SQIsignSignLvl1}, {@link SQIsignSignLvl3},
 * {@link SQIsignSignLvl5}, each of which supplies a {@link Params} bundle
 * with the level-specific precomp constants, action matrices, and four
 * functional callbacks.</p>
 */
final class SQIsignSign
{
    private SQIsignSign()
    {
    }

    interface IdealToIsogeny
    {
        int arbitraryIsogenyEvaluation(EcBasis basis, EcCurve codomain,
                                       QuatLeftIdeal lideal, SecureRandom random);
    }

    interface ToHint
    {
        int toHint(EcBasis basis, EcCurve curve, int torsionEvenPower);
    }

    interface ChainComputeAndEvalRandomized
    {
        int chainComputeAndEvalRandomized(int n, ThetaCoupleCurve E12,
                                          ThetaKernelCouplePoints ker, boolean extraTorsion,
                                          ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                          SecureRandom random);
    }

    interface HashToChallenge
    {
        BigInteger hashToChallenge(EcCurve pkCurve, EcCurve comCurve, byte[] message);
    }

    /** Level-specific config bundle. Immutable. */
    static final class Params
    {
        final GfField field;
        final BigInteger comDegree;
        final QuatAlg quatalgPinfty;
        final int quatPrimalityNumIter;
        final int quatEquivBoundCoeff;
        final QuatRepresentIntegerParams representParams;
        final QuatLattice maxordO0;
        final Ibz quatPrimeCofactor;
        final int sqisignResponseLength;
        final int torsionEvenPower;
        final int hdExtraTorsion;
        final long pCofactorFor2f;
        final Ibz ibzTorsionPlus2Power;
        // Action matrices from CURVES_WITH_ENDOMORPHISMS[0].
        final Ibz[][] actionI;
        final Ibz[][] actionJ;
        final Ibz[][] actionGen2;
        final Ibz[][] actionGen3;
        final Ibz[][] actionGen4;
        // Level-specific dispatch.
        final IdealToIsogeny idealToIsogeny;
        final ToHint toHint;
        final ChainComputeAndEvalRandomized chainRandomized;
        final HashToChallenge hashToChallenge;

        Params(GfField field,
               BigInteger comDegree,
               QuatAlg quatalgPinfty,
               int quatPrimalityNumIter, int quatEquivBoundCoeff,
               QuatRepresentIntegerParams representParams,
               QuatLattice maxordO0, Ibz quatPrimeCofactor,
               int sqisignResponseLength, int torsionEvenPower, int hdExtraTorsion,
               long pCofactorFor2f, Ibz ibzTorsionPlus2Power,
               Ibz[][] actionI, Ibz[][] actionJ,
               Ibz[][] actionGen2, Ibz[][] actionGen3, Ibz[][] actionGen4,
               IdealToIsogeny idealToIsogeny, ToHint toHint,
               ChainComputeAndEvalRandomized chainRandomized,
               HashToChallenge hashToChallenge)
        {
            this.field = field;
            this.comDegree = comDegree;
            this.quatalgPinfty = quatalgPinfty;
            this.quatPrimalityNumIter = quatPrimalityNumIter;
            this.quatEquivBoundCoeff = quatEquivBoundCoeff;
            this.representParams = representParams;
            this.maxordO0 = maxordO0;
            this.quatPrimeCofactor = quatPrimeCofactor;
            this.sqisignResponseLength = sqisignResponseLength;
            this.torsionEvenPower = torsionEvenPower;
            this.hdExtraTorsion = hdExtraTorsion;
            this.pCofactorFor2f = pCofactorFor2f;
            this.ibzTorsionPlus2Power = ibzTorsionPlus2Power;
            this.actionI = actionI;
            this.actionJ = actionJ;
            this.actionGen2 = actionGen2;
            this.actionGen3 = actionGen3;
            this.actionGen4 = actionGen4;
            this.idealToIsogeny = idealToIsogeny;
            this.toHint = toHint;
            this.chainRandomized = chainRandomized;
            this.hashToChallenge = hashToChallenge;
        }
    }

    static int commit(Params p, EcCurve eCom, EcBasis basisEvenCom,
                      QuatLeftIdeal lidealCom, SecureRandom random)
    {
        int ok = Normeq.samplingRandomIdealO0GivenNorm(
            lidealCom, new Ibz(p.comDegree), /* isPrime = */ true,
            p.representParams, /* primeCofactor = */ null, random);
        if (ok != 1) return 0;
        ok = LllApplications.primeNormReducedEquivalent(lidealCom, p.quatalgPinfty,
            p.quatPrimalityNumIter, p.quatEquivBoundCoeff, random);
        if (ok != 1) return 0;
        return p.idealToIsogeny.arbitraryIsogenyEvaluation(basisEvenCom, eCom, lidealCom, random);
    }

    static void computeChallengeIdealSignature(Params p, QuatLeftIdeal lidealChallTwo,
                                               SQIsignSignature sig, SQIsignSecretKeyData sk)
    {
        Ibz[] vec = new Ibz[]{new Ibz(1), new Ibz(sig.challCoeff)};
        Ibz[] tmp = new Ibz[]{new Ibz(), new Ibz()};
        IbzMat.eval2x2(tmp, sk.matBAcanToBA0Two, vec);
        vec[0] = tmp[0];
        vec[1] = tmp[1];
        Id2IsoHelpers.kernelDlogsToIdealEven(lidealChallTwo, vec, p.torsionEvenPower,
            p.actionI, p.actionJ, p.actionGen4,
            p.maxordO0, p.quatalgPinfty, p.ibzTorsionPlus2Power, p.torsionEvenPower);
    }

    static int sampleResponse(Params p, QuatAlg.Elem x, QuatLattice lattice,
                              Ibz latticeContent, SecureRandom random)
    {
        BigInteger boundV = BigInteger.ONE.shiftLeft(p.sqisignResponseLength)
            .subtract(BigInteger.ONE).multiply(latticeContent.v);
        Ibz bound = new Ibz(boundV);
        return LatBall.sampleFromBall(x, lattice, p.quatalgPinfty, bound, random);
    }

    static int computeResponseQuatElement(Params p, QuatAlg.Elem respQuat, Ibz latticeContent,
                                          SQIsignSecretKeyData sk,
                                          QuatLeftIdeal lidealChallTwo,
                                          QuatLeftIdeal lidealCommit, SecureRandom random)
    {
        QuatLeftIdeal lidealChallSecret = new QuatLeftIdeal();
        QuatLattice latCommit = new QuatLattice();
        QuatLattice latticeHomChallToCom = new QuatLattice();

        QuatLeftIdeal.inter(lidealChallSecret, lidealChallTwo, sk.secretIdeal);
        QuatLattice.conjugateWithoutHnf(latCommit, lidealCommit.lattice);
        QuatLattice.intersect(latticeHomChallToCom, lidealChallSecret.lattice, latCommit);
        Ibz.mul(latticeContent, lidealChallSecret.norm, lidealCommit.norm);
        return sampleResponse(p, respQuat, latticeHomChallToCom, latticeContent, random);
    }

    static void computeBacktrackingSignature(Params p, SQIsignSignature sig,
                                             QuatAlg.Elem respQuat,
                                             Ibz latticeContent, Ibz remain)
    {
        Ibz content = new Ibz();
        Ibz[] dummyCoord = IbzVec.init4();
        QuatAlg.makePrimitive(dummyCoord, content, respQuat, p.maxordO0);
        Ibz.mul(respQuat.denom, respQuat.denom, content);
        int backtracking = Ibz.twoAdic(content);
        sig.backtracking = backtracking;
        BigInteger tmp = BigInteger.ONE.shiftLeft(backtracking);
        Ibz tmpIbz = new Ibz(tmp);
        Ibz.div(latticeContent, remain, latticeContent, tmpIbz);
    }

    /** Bundle of outputs from {@link #computeRandomAuxNormAndHelpers}. */
    static final class RandomAuxNormResult
    {
        int powDim2DegResp;
        final Ibz randomAuxNorm = new Ibz();
        final Ibz degreeRespInv = new Ibz();
        final Ibz remain = new Ibz();
    }

    static RandomAuxNormResult computeRandomAuxNormAndHelpers(Params p,
        SQIsignSignature sig, Ibz latticeContent,
        QuatAlg.Elem respQuat, QuatLeftIdeal lidealComResp, QuatLeftIdeal lidealCommit)
    {
        RandomAuxNormResult res = new RandomAuxNormResult();
        Ibz tmp = new Ibz();
        Ibz degreeFullResp = new Ibz();
        Ibz degreeOddResp = new Ibz();
        Ibz normD = new Ibz();

        QuatAlg.norm(degreeFullResp, normD, respQuat, p.quatalgPinfty);
        Ibz.div(degreeFullResp, res.remain, degreeFullResp, latticeContent);

        int expDiadicValFullResp = Ibz.twoAdic(degreeFullResp);
        sig.twoRespLength = expDiadicValFullResp;

        BigInteger twoPow = BigInteger.ONE.shiftLeft(expDiadicValFullResp);
        Ibz.set(tmp, 0);
        tmp.v = twoPow;
        Ibz.div(degreeOddResp, res.remain, degreeFullResp, tmp);

        QuatAlg.conj(respQuat, respQuat);

        Ibz.mul(tmp, lidealCommit.norm, degreeOddResp);
        QuatLeftIdeal.create(lidealComResp, respQuat, tmp, p.maxordO0, p.quatalgPinfty);

        res.powDim2DegResp = p.sqisignResponseLength - expDiadicValFullResp - sig.backtracking;

        BigInteger twoPowPdr = BigInteger.ONE.shiftLeft(res.powDim2DegResp);
        Ibz.set(res.remain, 0);
        res.remain.v = twoPowPdr;
        Ibz.sub(res.randomAuxNorm, res.remain, degreeOddResp);

        res.remain.v = res.remain.v.shiftLeft(p.hdExtraTorsion);

        try
        {
            res.degreeRespInv.v = degreeOddResp.v.modInverse(res.remain.v);
        }
        catch (ArithmeticException e)
        {
            throw new IllegalStateException(
                "computeRandomAuxNormAndHelpers: degreeOddResp not invertible mod remain");
        }
        return res;
    }

    static int evaluateRandomAuxIsogenySignature(Params p, EcCurve eAux, EcBasis bAux,
                                                 Ibz norm, QuatLeftIdeal lidealComResp,
                                                 SecureRandom random)
    {
        QuatLeftIdeal lidealAux = new QuatLeftIdeal();
        QuatLeftIdeal lidealAuxRespCom = new QuatLeftIdeal();

        int ok = Normeq.samplingRandomIdealO0GivenNorm(lidealAux, norm, /* isPrime */ false,
            p.representParams, p.quatPrimeCofactor, random);
        if (ok != 1) return 0;

        QuatLeftIdeal.inter(lidealAuxRespCom, lidealComResp, lidealAux);
        return p.idealToIsogeny.arbitraryIsogenyEvaluation(bAux, eAux, lidealAuxRespCom, random);
    }

    static int computeChallengeCodomainSignature(Params p, SQIsignSignature sig,
                                                 SQIsignSecretKeyData sk,
                                                 EcCurve eChall, EcCurve eChall2,
                                                 EcBasis bChall2)
    {
        EcIsogEven phiChall = new EcIsogEven();
        EcBasis basSk = new EcBasis();
        EcBasis.copy(basSk, sk.canonicalBasis);

        EcCurve.copy(phiChall.curve, sk.curve);
        phiChall.length = p.torsionEvenPower - sig.backtracking;

        EcOps.normalizeCurveAndA24(sk.curve);
        int ladderOk = EcLadder.ladder3pt(phiChall.kernel, sig.challCoeff,
            p.torsionEvenPower, basSk.P, basSk.Q, basSk.PmQ, sk.curve);
        if (ladderOk != 1) return 0;

        if (sig.backtracking > 0)
        {
            EcLadder.dblIter(phiChall.kernel, sig.backtracking, phiChall.kernel, sk.curve);
        }

        int evalRet = EcIsogChains.evalEven(eChall, phiChall, null, 0);
        if (evalRet != 0) return 0;

        EcIsom isom = new EcIsom();
        int isomRet = EcIsogChains.isomorphism(isom, eChall2, eChall);
        if (isomRet != 0) return 0;
        EcIsogChains.isoEval(eChall2.field, bChall2.P, isom);
        EcIsogChains.isoEval(eChall2.field, bChall2.Q, isom);
        EcIsogChains.isoEval(eChall2.field, bChall2.PmQ, isom);
        return 1;
    }

    static void setAuxCurveSignature(SQIsignSignature sig, EcCurve eAux)
    {
        EcOps.normalizeCurve(eAux);
        Fp2.copy(sig.eAuxA, eAux.A);
    }

    static void computeAndSetBasisChangeMatrix(Params p, SQIsignSignature sig,
                                               EcBasis bAux2, EcBasis bChall2,
                                               EcCurve eAux2, EcCurve eChall, int f)
    {
        EcBasis bCanChall = new EcBasis();
        EcBasis bAux2Can = new EcBasis();
        sig.hintChall = p.toHint.toHint(bCanChall, eChall, p.torsionEvenPower);
        sig.hintAux = p.toHint.toHint(bAux2Can, eAux2, p.torsionEvenPower);

        BigInteger[][] matBaux2ToCan = EcDlog.changeOfBasisMatrixTateInvert(
            bAux2Can, bAux2, eAux2, f, p.torsionEvenPower, p.pCofactorFor2f);
        if (matBaux2ToCan == null)
        {
            throw new IllegalStateException(
                "computeAndSetBasisChangeMatrix: dlog on B_aux_2 failed");
        }

        Ibz[][] matIbz = IbzMat.init2x2();
        matIbz[0][0].v = matBaux2ToCan[0][0];
        matIbz[0][1].v = matBaux2ToCan[0][1];
        matIbz[1][0].v = matBaux2ToCan[1][0];
        matIbz[1][1].v = matBaux2ToCan[1][1];
        Id2IsoHelpers.matrixApplicationEvenBasis(bChall2, eChall, matIbz, f);

        BigInteger[][] matChall = EcDlog.changeOfBasisMatrixTate(
            bChall2, bCanChall, eChall, f, p.torsionEvenPower, p.pCofactorFor2f);
        if (matChall == null)
        {
            throw new IllegalStateException(
                "computeAndSetBasisChangeMatrix: dlog on B_chall_2 failed");
        }
        sig.matBchallCanToBChall[0][0] = matChall[0][0];
        sig.matBchallCanToBChall[0][1] = matChall[0][1];
        sig.matBchallCanToBChall[1][0] = matChall[1][0];
        sig.matBchallCanToBChall[1][1] = matChall[1][1];
    }

    static int computeDim2IsogenyChallenge(Params p, ThetaCoupleCurveWithBasis codomain,
                                           ThetaCoupleCurveWithBasis domain,
                                           Ibz degreeRespInv, int powDim2DegResp,
                                           int expDiadicValFullResp, int reducedOrder,
                                           SecureRandom random)
    {
        ThetaCoupleCurve ecomXeaux = new ThetaCoupleCurve();
        EcCurve.copy(ecomXeaux.E1, domain.E1);
        EcCurve.copy(ecomXeaux.E2, domain.E2);

        ThetaKernelCouplePoints dimTwoKer = new ThetaKernelCouplePoints();
        HdOps.copyBasesToKernel(dimTwoKer, domain.B1, domain.B2);

        EcLadder.mul(dimTwoKer.T1.P2, degreeRespInv.v, reducedOrder, dimTwoKer.T1.P2, ecomXeaux.E2);
        EcLadder.mul(dimTwoKer.T2.P2, degreeRespInv.v, reducedOrder, dimTwoKer.T2.P2, ecomXeaux.E2);
        EcLadder.mul(dimTwoKer.T1m2.P2, degreeRespInv.v, reducedOrder, dimTwoKer.T1m2.P2, ecomXeaux.E2);

        if (expDiadicValFullResp > 0)
        {
            HdOps.doubleCouplePointIter(dimTwoKer.T1, expDiadicValFullResp, dimTwoKer.T1, ecomXeaux);
            HdOps.doubleCouplePointIter(dimTwoKer.T2, expDiadicValFullResp, dimTwoKer.T2, ecomXeaux);
            HdOps.doubleCouplePointIter(dimTwoKer.T1m2, expDiadicValFullResp, dimTwoKer.T1m2, ecomXeaux);
        }

        ThetaCouplePoint[] pushed = new ThetaCouplePoint[3];
        for (int i = 0; i < 3; i++) pushed[i] = new ThetaCouplePoint();
        EcPoint.copy(pushed[0].P1, domain.B1.P);
        EcOps.pointInit(pushed[0].P2);
        EcPoint.copy(pushed[1].P1, domain.B1.Q);
        EcOps.pointInit(pushed[1].P2);
        EcPoint.copy(pushed[2].P1, domain.B1.PmQ);
        EcOps.pointInit(pushed[2].P2);

        ThetaCoupleCurve codomainProduct = new ThetaCoupleCurve();
        int chainRet = p.chainRandomized.chainComputeAndEvalRandomized(
            powDim2DegResp, ecomXeaux, dimTwoKer, true, codomainProduct, pushed, 3, random);
        if (chainRet == 0) return 0;

        EcCurve.copy(codomain.E1, codomainProduct.E2);
        EcCurve.copy(codomain.E2, codomainProduct.E1);

        EcPoint.copy(codomain.B1.P, pushed[0].P2);
        EcPoint.copy(codomain.B1.Q, pushed[1].P2);
        EcPoint.copy(codomain.B1.PmQ, pushed[2].P2);
        EcPoint.copy(codomain.B2.P, pushed[0].P1);
        EcPoint.copy(codomain.B2.Q, pushed[1].P1);
        EcPoint.copy(codomain.B2.PmQ, pushed[2].P1);
        return 1;
    }

    static int computeSmallChainIsogenySignature(Params p, EcCurve eChall2, EcBasis bChall2,
                                                 QuatAlg.Elem respQuat, int powDim2DegResp,
                                                 int length)
    {
        Ibz twoPow = new Ibz(BigInteger.ONE.shiftLeft(length));
        QuatLeftIdeal lidealRespTwo = new QuatLeftIdeal();
        QuatLeftIdeal.create(lidealRespTwo, respQuat, twoPow, p.maxordO0, p.quatalgPinfty);

        Ibz[] vecRespTwo = new Ibz[]{new Ibz(), new Ibz()};
        Id2IsoHelpers.idealToKernelDlogsEven(vecRespTwo, lidealRespTwo,
            p.actionGen2, p.actionGen3, p.actionGen4, p.quatalgPinfty);

        EcPoint[] points = new EcPoint[]{new EcPoint(), new EcPoint(), new EcPoint()};
        EcPoint.copy(points[0], bChall2.P);
        EcPoint.copy(points[1], bChall2.Q);
        EcPoint.copy(points[2], bChall2.PmQ);

        EcLadder.dblIterBasis(bChall2, powDim2DegResp + p.hdExtraTorsion, bChall2, eChall2);

        EcPoint ker = new EcPoint();
        int kerOk = Id2IsoHelpers.ecBiscalarMulIbzVec(ker, vecRespTwo, length, bChall2, eChall2);
        if (kerOk != 1) return 0;

        int evalRet = EcIsogChains.evalSmallChain(eChall2, ker, length, points, 3, true);
        if (evalRet != 0) return 0;

        EcPoint.copy(bChall2.P, points[0]);
        EcPoint.copy(bChall2.Q, points[1]);
        EcPoint.copy(bChall2.PmQ, points[2]);
        return 1;
    }

    static int protocolsSign(Params p, SQIsignSignature sig,
                             EcCurve pkCurve, SQIsignSecretKeyData sk,
                             byte[] message, SecureRandom random)
    {
        Ibz remain = new Ibz();
        Ibz latticeContent = new Ibz();
        QuatAlg.Elem respQuat = new QuatAlg.Elem();
        QuatLeftIdeal lidealCommit = new QuatLeftIdeal();
        QuatLeftIdeal lidealComResp = new QuatLeftIdeal();

        ThetaCoupleCurveWithBasis ecomEaux = new ThetaCoupleCurveWithBasis();
        ThetaCoupleCurveWithBasis eaux2Echall2 = new ThetaCoupleCurveWithBasis();
        ecomEaux.E1.field = p.field;
        ecomEaux.E2.field = p.field;
        eaux2Echall2.E1.field = p.field;
        eaux2Echall2.E2.field = p.field;

        EcCurve eChall = new EcCurve();
        eChall.field = p.field;
        EcCurve.copy(eChall, sk.curve);

        int reducedOrder = 0;
        RandomAuxNormResult auxRes;

        int ret = 0;
        int maxAttempts = 64;
        for (int attempt = 0; attempt < maxAttempts && ret == 0; attempt++)
        {
            int ok = commit(p, ecomEaux.E1, ecomEaux.B1, lidealCommit, random);
            if (ok != 1) continue;

            sig.challCoeff = p.hashToChallenge.hashToChallenge(pkCurve, ecomEaux.E1, message);

            QuatLeftIdeal lidealChallTwo = new QuatLeftIdeal();
            computeChallengeIdealSignature(p, lidealChallTwo, sig, sk);

            int respOk;
            try
            {
                respOk = computeResponseQuatElement(p, respQuat, latticeContent,
                    sk, lidealChallTwo, lidealCommit, random);
            }
            catch (RuntimeException e)
            {
                continue;
            }
            if (respOk != 1) continue;

            computeBacktrackingSignature(p, sig, respQuat, latticeContent, remain);

            try
            {
                auxRes = computeRandomAuxNormAndHelpers(p, sig, latticeContent,
                    respQuat, lidealComResp, lidealCommit);
            }
            catch (RuntimeException e)
            {
                continue;
            }
            int powDim2DegResp = auxRes.powDim2DegResp;

            if (powDim2DegResp > 0)
            {
                int auxOk = evaluateRandomAuxIsogenySignature(p,
                    ecomEaux.E2, ecomEaux.B2, auxRes.randomAuxNorm, lidealComResp, random);
                if (auxOk != 1) continue;

                reducedOrder = powDim2DegResp + p.hdExtraTorsion + sig.twoRespLength;
                int dblIters = p.torsionEvenPower - reducedOrder;
                if (dblIters > 0)
                {
                    EcLadder.dblIterBasis(ecomEaux.B1, dblIters, ecomEaux.B1, ecomEaux.E1);
                    EcLadder.dblIterBasis(ecomEaux.B2, dblIters, ecomEaux.B2, ecomEaux.E2);
                }

                int dim2Ok = computeDim2IsogenyChallenge(p, eaux2Echall2, ecomEaux,
                    auxRes.degreeRespInv, powDim2DegResp,
                    sig.twoRespLength, reducedOrder, random);
                if (dim2Ok != 1) continue;
            }
            else
            {
                EcCurve.copy(eaux2Echall2.E1, ecomEaux.E1);
                EcCurve.copy(eaux2Echall2.E2, ecomEaux.E1);
                reducedOrder = sig.twoRespLength;
                int dblIters = p.torsionEvenPower - reducedOrder;
                if (dblIters > 0)
                {
                    EcLadder.dblIterBasis(eaux2Echall2.B1, dblIters, ecomEaux.B1, ecomEaux.E1);
                    EcLadder.dblIterBasis(eaux2Echall2.B1, dblIters, ecomEaux.B1, ecomEaux.E1);
                }
                EcBasis.copy(eaux2Echall2.B2, eaux2Echall2.B1);
            }

            if (sig.twoRespLength > 0)
            {
                int smallOk = computeSmallChainIsogenySignature(p,
                    eaux2Echall2.E2, eaux2Echall2.B2, respQuat,
                    powDim2DegResp, sig.twoRespLength);
                if (smallOk != 1) continue;
            }

            int codomainOk = computeChallengeCodomainSignature(p, sig, sk,
                eChall, eaux2Echall2.E2, eaux2Echall2.B2);
            if (codomainOk != 1) continue;

            ret = 1;
        }

        if (ret != 1) return 0;

        setAuxCurveSignature(sig, eaux2Echall2.E1);
        computeAndSetBasisChangeMatrix(p, sig, eaux2Echall2.B1, eaux2Echall2.B2,
            eaux2Echall2.E1, eChall, reducedOrder);
        return 1;
    }
}
