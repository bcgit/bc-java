package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Lvl1 driver for the shared {@link ThetaChainCompute} engine. Wires the
 * lvl1 field instance and {@code HdSplittingTransformsLvl1} arrays in,
 * exposing the four C-mirroring entry points.
 */
final class ThetaChainLvl1
{
    private ThetaChainLvl1()
    {
    }

    private static int chainComputeAndEvalImpl(int n, ThetaCoupleCurve E12,
                                                ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                                boolean verify, boolean randomize,
                                                java.security.SecureRandom random)
    {
        return ThetaChainCompute.chainComputeAndEvalImpl(GfFieldLvl1.INSTANCE,
            HdSplittingTransformsLvl1.FP2_CONSTANTS,
            HdSplittingTransformsLvl1.EVEN_INDEX,
            HdSplittingTransformsLvl1.CHI_EVAL,
            HdSplittingTransformsLvl1.SPLITTING_TRANSFORM_INDICES,
            HdSplittingTransformsLvl1.NORMALIZATION_TRANSFORM_INDICES,
            n, E12, ker, extraTorsion, E34, P12, numP, verify, randomize, random);
    }

    /** {@code theta_chain_compute_and_eval}: standard entry. */
    public static int chainComputeAndEval(int n, ThetaCoupleCurve E12,
                                          ThetaKernelCouplePoints ker, boolean extraTorsion,
                                          ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP)
    {
        return chainComputeAndEvalImpl(n, E12, ker, extraTorsion, E34, P12, numP, false, false, null);
    }

    /** {@code theta_chain_compute_and_eval_verify}: with extra isotropy checks. */
    public static int chainComputeAndEvalVerify(int n, ThetaCoupleCurve E12,
                                                ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP)
    {
        return chainComputeAndEvalImpl(n, E12, ker, extraTorsion, E34, P12, numP, true, false, null);
    }

    /** {@code theta_chain_compute_and_eval_randomized}: with random
     *  normalisation matrix (signing-side only). */
    public static int chainComputeAndEvalRandomized(int n, ThetaCoupleCurve E12,
                                                    ThetaKernelCouplePoints ker, boolean extraTorsion,
                                                    ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                                    java.security.SecureRandom random)
    {
        return chainComputeAndEvalImpl(n, E12, ker, extraTorsion, E34, P12, numP, false, true, random);
    }
}
