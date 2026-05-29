package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Per-extremal-order represent-integer parameter bundles for SQIsign
 * level 5. Mirrors {@code QuatRepresentIntegerParamsLvl1} but indexes the
 * 7 extremal orders of lvl5 (1 standard + 6 alternates).
 */
final class QuatRepresentIntegerParamsLvl5
{
    /** Quaternion algebra over Q ramified at the lvl5 prime + infinity. */
    public static final QuatAlg QUATALG_PINFTY = new QuatAlg(new Ibz(PrecompLvl5.P));

    /** Per-extremal-order parameter bundles (length 7). */
    public static final QuatRepresentIntegerParams[] INSTANCES;

    /** Convenience alias for {@code INSTANCES[0]} — the standard order. */
    public static final QuatRepresentIntegerParams INSTANCE;

    static
    {
        INSTANCES = new QuatRepresentIntegerParams[ExtremalOrdersLvl5.NUM_EXTREMAL_ORDERS];
        for (int i = 0; i < ExtremalOrdersLvl5.NUM_EXTREMAL_ORDERS; i++)
        {
            INSTANCES[i] = new QuatRepresentIntegerParams(
                PrecompLvl5.QUAT_PRIMALITY_NUM_ITER,
                ExtremalOrdersLvl5.EXTREMAL_ORDERS[i],
                QUATALG_PINFTY);
        }
        INSTANCE = INSTANCES[0];
    }

    private QuatRepresentIntegerParamsLvl5()
    {
    }
}
