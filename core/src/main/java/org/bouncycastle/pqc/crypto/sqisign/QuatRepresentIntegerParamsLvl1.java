package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Pre-wired {@link QuatRepresentIntegerParams} for SQIsign level 1, mirror of
 * the C {@code QUAT_represent_integer_params} in quaternion_data.c lvl1.
 *
 * <p>Bundles {@link PrecompLvl1#QUAT_PRIMALITY_NUM_ITER} with
 * {@link ExtremalOrdersLvl1#STANDARD_EXTREMAL_ORDER} (which the C code uses
 * as the default {@code .order} field) and {@link PrecompLvl1#QUATALG_PINFTY}.
 * </p>
 */
final class QuatRepresentIntegerParamsLvl1
{
    /**
     * Alias for {@link PrecompLvl1#QUATALG_PINFTY}. Mirrors the lvl3/lvl5
     * placement so cross-level callers can reference {@code
     * QuatRepresentIntegerParamsLvlN.QUATALG_PINFTY} uniformly.
     */
    public static final QuatAlg QUATALG_PINFTY = PrecompLvl1.QUATALG_PINFTY;

    /**
     * The level-1 represent-integer parameter bundle for the standard
     * extremal order, ready for handing to
     * {@link org.bouncycastle.pqc.crypto.sqisign.Normeq#representInteger}
     * and {@link org.bouncycastle.pqc.crypto.sqisign.Normeq#samplingRandomIdealO0GivenNorm}.
     *
     * <p>Reference-equal to {@link #INSTANCES}{@code [0]}.</p>
     */
    public static final QuatRepresentIntegerParams INSTANCE;

    /**
     * Per-extremal-order represent-integer parameter bundles, indexed
     * 0..6. Index 0 is the standard order O₀; indices 1..6 are the
     * alternate extremal orders. {@link org.bouncycastle.pqc.crypto.sqisign.Dim2Id2IsoClapotis}
     * indexes this directly to invoke {@code representInteger} per order.
     */
    public static final QuatRepresentIntegerParams[] INSTANCES;

    static
    {
        INSTANCES = new QuatRepresentIntegerParams[ExtremalOrdersLvl1.NUM_EXTREMAL_ORDERS];
        for (int i = 0; i < ExtremalOrdersLvl1.NUM_EXTREMAL_ORDERS; i++)
        {
            INSTANCES[i] = new QuatRepresentIntegerParams(
                PrecompLvl1.QUAT_PRIMALITY_NUM_ITER,
                ExtremalOrdersLvl1.EXTREMAL_ORDERS[i],
                PrecompLvl1.QUATALG_PINFTY);
        }
        INSTANCE = INSTANCES[0];
    }

    private QuatRepresentIntegerParamsLvl1()
    {
    }
}
