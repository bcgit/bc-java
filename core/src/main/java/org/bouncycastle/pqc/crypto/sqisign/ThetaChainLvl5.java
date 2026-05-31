package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Lvl5 driver for the shared {@link ThetaChainCompute} engine.
 */
final class ThetaChainLvl5
{
    private ThetaChainLvl5()
    {
    }

    private static int chainComputeAndEvalImpl(int n, ThetaCoupleCurve E12,
                                                ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                                boolean verify, boolean randomize,
                                                java.security.SecureRandom random)
    {
        return ThetaChainCompute.chainComputeAndEvalImpl(GfFieldLvl5.INSTANCE,
            HdSplittingTransformsLvl5.FP2_CONSTANTS,
            HdSplittingTransformsLvl5.EVEN_INDEX,
            HdSplittingTransformsLvl5.CHI_EVAL,
            HdSplittingTransformsLvl5.SPLITTING_TRANSFORM_INDICES,
            HdSplittingTransformsLvl5.NORMALIZATION_TRANSFORM_INDICES,
            n, E12, ker, extraTorsion, E34, P12, numP, verify, randomize, random);
    }

    public static int chainComputeAndEval(int n, ThetaCoupleCurve E12,
                                          ThetaKernelCouplePoints ker, boolean extraTorsion,
                                          ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP)
    {
        return chainComputeAndEvalImpl(n, E12, ker, extraTorsion, E34, P12, numP, false, false, null);
    }

    public static int chainComputeAndEvalVerify(int n, ThetaCoupleCurve E12,
                                                ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP)
    {
        return chainComputeAndEvalImpl(n, E12, ker, extraTorsion, E34, P12, numP, true, false, null);
    }

    public static int chainComputeAndEvalRandomized(int n, ThetaCoupleCurve E12,
                                                    ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                    ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                                    java.security.SecureRandom random)
    {
        return chainComputeAndEvalImpl(n, E12, ker, extraTorsion, E34, P12, numP, false, true, random);
    }
}
