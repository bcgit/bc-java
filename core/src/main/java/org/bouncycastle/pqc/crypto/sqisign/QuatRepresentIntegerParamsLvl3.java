package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Per-extremal-order represent-integer parameter bundles for SQIsign
 * level 3. Mirrors {@code QuatRepresentIntegerParamsLvl1} but indexes the
 * 8 extremal orders of lvl3 (1 standard + 7 alternates).
 */
final class QuatRepresentIntegerParamsLvl3
{
    /** Quaternion algebra over Q ramified at the lvl3 prime + infinity. */
    public static final QuatAlg QUATALG_PINFTY = new QuatAlg(new Ibz(PrecompLvl3.P));

    /** Per-extremal-order parameter bundles (length 8). */
    public static final QuatRepresentIntegerParams[] INSTANCES;

    /** Convenience alias for {@code INSTANCES[0]} — the standard order. */
    public static final QuatRepresentIntegerParams INSTANCE;

    static
    {
        INSTANCES = new QuatRepresentIntegerParams[ExtremalOrdersLvl3.NUM_EXTREMAL_ORDERS];
        for (int i = 0; i < ExtremalOrdersLvl3.NUM_EXTREMAL_ORDERS; i++)
        {
            INSTANCES[i] = new QuatRepresentIntegerParams(
                PrecompLvl3.QUAT_PRIMALITY_NUM_ITER,
                ExtremalOrdersLvl3.EXTREMAL_ORDERS[i],
                QUATALG_PINFTY);
        }
        INSTANCE = INSTANCES[0];
    }

    private QuatRepresentIntegerParamsLvl3()
    {
    }
}
