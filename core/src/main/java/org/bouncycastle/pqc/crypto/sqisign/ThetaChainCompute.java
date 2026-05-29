package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Level-independent theta-isogeny chain driver. Java port of
 * {@code _theta_chain_compute_impl} and its three entry wrappers from
 * {@code theta_isogenies.c}.
 *
 * <p>Driven from {@link ThetaChainLvl1}, {@link ThetaChainLvl3},
 * {@link ThetaChainLvl5}, each of which passes the level-specific
 * {@code HdSplittingTransformsLvlN} arrays through to the final splitting
 * step.</p>
 */
final class ThetaChainCompute
{
    private ThetaChainCompute()
    {
    }

    static int chainComputeAndEvalImpl(GfField field,
                                       Fp2[] splittingFp2Constants,
                                       int[][] splittingEvenIndex,
                                       int[][] splittingChiEval,
                                       int[][][] splittingTransformIndices,
                                       int[][][] splittingNormalizationIndices,
                                       int n, ThetaCoupleCurve E12,
                                       ThetaKernelCouplePoints ker, boolean extraTorsion,
                                       ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                       boolean verify, boolean randomize,
                                       java.security.SecureRandom random)
    {
        ThetaCoupleJacPoint xyT1 = new ThetaCoupleJacPoint();
        ThetaCoupleJacPoint xyT2 = new ThetaCoupleJacPoint();

        EcBasis bas1 = new EcBasis();
        EcBasis bas2 = new EcBasis();
        EcPoint.copy(bas1.P, ker.T1.P1);
        EcPoint.copy(bas1.Q, ker.T2.P1);
        EcPoint.copy(bas1.PmQ, ker.T1m2.P1);
        EcPoint.copy(bas2.P, ker.T1.P2);
        EcPoint.copy(bas2.Q, ker.T2.P2);
        EcPoint.copy(bas2.PmQ, ker.T1m2.P2);

        if (EcBasisOps.liftBasis(field, xyT1.P1, xyT2.P1, bas1, E12.E1) == 0)
        {
            return 0;
        }
        if (EcBasisOps.liftBasis(field, xyT1.P2, xyT2.P2, bas2, E12.E2) == 0)
        {
            return 0;
        }

        int extra = extraTorsion ? HdOps.HD_EXTRA_TORSION : 0;

        ThetaPoint[] pts = new ThetaPoint[Math.max(numP, 1)];
        for (int i = 0; i < pts.length; i++)
        {
            pts[i] = new ThetaPoint();
        }

        int space = 1;
        for (int i = 1; i < n; i *= 2)
        {
            space++;
        }
        int[] todo = new int[space];
        todo[0] = n - 2 + extra;

        int current = 0;
        ThetaCoupleJacPoint[] jacQ1 = new ThetaCoupleJacPoint[space];
        ThetaCoupleJacPoint[] jacQ2 = new ThetaCoupleJacPoint[space];
        for (int i = 0; i < space; i++)
        {
            jacQ1[i] = new ThetaCoupleJacPoint();
            jacQ2[i] = new ThetaCoupleJacPoint();
        }
        ThetaCoupleJacPoint.copy(jacQ1[0], xyT1);
        ThetaCoupleJacPoint.copy(jacQ2[0], xyT2);

        while (todo[current] != 1)
        {
            current++;
            int numDbls = todo[current - 1] >= 16 ? todo[current - 1] / 2 : todo[current - 1] - 1;
            HdOps.doubleCoupleJacPointIter(jacQ1[current], numDbls, jacQ1[current - 1], E12);
            HdOps.doubleCoupleJacPointIter(jacQ2[current], numDbls, jacQ2[current - 1], E12);
            todo[current] = todo[current - 1] - numDbls;
        }

        ThetaPoint[] thetaQ1 = new ThetaPoint[space];
        ThetaPoint[] thetaQ2 = new ThetaPoint[space];
        for (int i = 0; i < space; i++)
        {
            thetaQ1[i] = new ThetaPoint();
            thetaQ2[i] = new ThetaPoint();
        }

        ThetaGluing firstStep = new ThetaGluing();
        if (ThetaGluingCompute.gluingCompute(firstStep, E12, jacQ1[current], jacQ2[current], verify) == 0)
        {
            return 0;
        }
        for (int j = 0; j < numP; j++)
        {
            int ok = ThetaGluingEval.gluingEvalPointSpecialCase(field, pts[j], P12[j], firstStep);
            if (ok == 0)
            {
                return 0;
            }
        }
        for (int j = 0; j < current; j++)
        {
            ThetaGluingEval.gluingEvalBasis(field, thetaQ1[j], thetaQ2[j], jacQ1[j], jacQ2[j], firstStep);
            todo[j]--;
        }
        current--;

        ThetaStructure theta = new ThetaStructure();
        theta.field = E12.E1.field;
        Fp2.copy(theta.nullPoint.x, firstStep.codomain.x);
        Fp2.copy(theta.nullPoint.y, firstStep.codomain.y);
        Fp2.copy(theta.nullPoint.z, firstStep.codomain.z);
        Fp2.copy(theta.nullPoint.t, firstStep.codomain.t);
        theta.precomputation = false;
        ThetaOps.thetaPrecomputation(field, theta);

        ThetaIsogeny step = new ThetaIsogeny();

        for (int i = 1; current >= 0 && todo[current] != 0; i++)
        {
            while (todo[current] != 1)
            {
                current++;
                int numDbls = todo[current - 1] / 2;
                ThetaOps.doubleIter(field, thetaQ1[current], theta, thetaQ1[current - 1], numDbls);
                ThetaOps.doubleIter(field, thetaQ2[current], theta, thetaQ2[current - 1], numDbls);
                todo[current] = todo[current - 1] - numDbls;
            }

            int ret;
            if (i == n - 2)
            {
                ret = ThetaIsogenyCompute.compute(field, step, theta, thetaQ1[current], thetaQ2[current], false, false, verify);
            }
            else if (i == n - 1)
            {
                ret = ThetaIsogenyCompute.compute(field, step, theta, thetaQ1[current], thetaQ2[current], true, false, false);
            }
            else
            {
                ret = ThetaIsogenyCompute.compute(field, step, theta, thetaQ1[current], thetaQ2[current], false, true, verify);
            }
            if (ret == 0)
            {
                return 0;
            }

            for (int j = 0; j < numP; j++)
            {
                ThetaIsogenyCompute.eval(field, pts[j], step, pts[j]);
            }

            Fp2.copy(theta.nullPoint.x, step.codomain.nullPoint.x);
            Fp2.copy(theta.nullPoint.y, step.codomain.nullPoint.y);
            Fp2.copy(theta.nullPoint.z, step.codomain.nullPoint.z);
            Fp2.copy(theta.nullPoint.t, step.codomain.nullPoint.t);
            theta.precomputation = step.codomain.precomputation;

            for (int j = 0; j < current; j++)
            {
                ThetaIsogenyCompute.eval(field, thetaQ1[j], step, thetaQ1[j]);
                ThetaIsogenyCompute.eval(field, thetaQ2[j], step, thetaQ2[j]);
                todo[j]--;
            }
            current--;
        }

        if (!extraTorsion)
        {
            if (n >= 3)
            {
                ThetaIsogenyCompute.eval(field, thetaQ1[0], step, thetaQ1[0]);
                ThetaIsogenyCompute.eval(field, thetaQ2[0], step, thetaQ2[0]);
            }

            ThetaIsogenyCompute.compute4(field, step, theta, thetaQ1[0], thetaQ2[0], false, false);
            for (int j = 0; j < numP; j++)
            {
                ThetaIsogenyCompute.eval(field, pts[j], step, pts[j]);
            }
            Fp2.copy(theta.nullPoint.x, step.codomain.nullPoint.x);
            Fp2.copy(theta.nullPoint.y, step.codomain.nullPoint.y);
            Fp2.copy(theta.nullPoint.z, step.codomain.nullPoint.z);
            Fp2.copy(theta.nullPoint.t, step.codomain.nullPoint.t);
            theta.precomputation = step.codomain.precomputation;
            ThetaIsogenyCompute.eval(field, thetaQ1[0], step, thetaQ1[0]);
            ThetaIsogenyCompute.eval(field, thetaQ2[0], step, thetaQ2[0]);

            ThetaIsogenyCompute.compute2(field, step, theta, thetaQ1[0], thetaQ2[0], true, false);
            for (int j = 0; j < numP; j++)
            {
                ThetaIsogenyCompute.eval(field, pts[j], step, pts[j]);
            }
            Fp2.copy(theta.nullPoint.x, step.codomain.nullPoint.x);
            Fp2.copy(theta.nullPoint.y, step.codomain.nullPoint.y);
            Fp2.copy(theta.nullPoint.z, step.codomain.nullPoint.z);
            Fp2.copy(theta.nullPoint.t, step.codomain.nullPoint.t);
            theta.precomputation = step.codomain.precomputation;
        }

        ThetaSplitting lastStep = new ThetaSplitting();
        boolean isSplit = ThetaSplittingCompute.splittingCompute(field,
            splittingFp2Constants, splittingEvenIndex, splittingChiEval,
            splittingTransformIndices, splittingNormalizationIndices,
            lastStep, theta, extraTorsion ? 8 : -1, randomize, random);
        if (!isSplit)
        {
            return 0;
        }

        if (ThetaProductHelpers.productStructureToEllipticProduct(field, E34, lastStep.B) == 0)
        {
            return 0;
        }

        for (int j = 0; j < numP; j++)
        {
            ThetaIsogenyOps.applyIsomorphism(field, pts[j], lastStep.M, pts[j]);
            if (ThetaProductHelpers.pointToMontgomery(field, P12[j], pts[j], lastStep.B) == 0)
            {
                return 0;
            }
        }
        return 1;
    }
}
