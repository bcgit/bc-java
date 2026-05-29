package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Parameter bundle for {@link Normeq#representInteger}. Mirrors C
 * {@code quat_represent_integer_params_t}.
 */
final class QuatRepresentIntegerParams
{
    public final int primalityTestIterations;
    public final QuatExtremalMaximalOrder order;
    public final QuatAlg algebra;

    public QuatRepresentIntegerParams(int primalityTestIterations,
                                      QuatExtremalMaximalOrder order,
                                      QuatAlg algebra)
    {
        this.primalityTestIterations = primalityTestIterations;
        this.order = order;
        this.algebra = algebra;
    }
}
