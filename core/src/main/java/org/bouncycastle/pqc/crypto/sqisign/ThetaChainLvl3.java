package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Lvl3 driver for the shared {@link ThetaChainCompute} engine.
 */
final class ThetaChainLvl3
{
    private ThetaChainLvl3()
    {
    }

    private static int chainComputeAndEvalImpl(int n, ThetaCoupleCurve E12,
                                                ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                                boolean verify, boolean randomize,
                                                java.security.SecureRandom random)
    {
        return ThetaChainCompute.chainComputeAndEvalImpl(GfFieldLvl3.INSTANCE,
            HdSplittingTransformsLvl3.FP2_CONSTANTS,
            HdSplittingTransformsLvl3.EVEN_INDEX,
            HdSplittingTransformsLvl3.CHI_EVAL,
            HdSplittingTransformsLvl3.SPLITTING_TRANSFORM_INDICES,
            HdSplittingTransformsLvl3.NORMALIZATION_TRANSFORM_INDICES,
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
