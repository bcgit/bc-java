package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;


/**
 * Lvl5 driver for the shared {@link SQIsignKeyGen} engine.
 */
final class SQIsignKeyGenLvl5
{
    private SQIsignKeyGenLvl5()
    {
    }

    public static final class KeyPair
    {
        public final SQIsignSecretKeyData sk;
        public final int hintPk;

        public KeyPair(SQIsignSecretKeyData sk, int hintPk)
        {
            this.sk = sk;
            this.hintPk = hintPk;
        }
    }

    public static KeyPair protocolsKeygenFull(SecureRandom random)
    {
        SQIsignKeyGen.Result r = SQIsignKeyGen.protocolsKeygenFull(
            PrecompLvl5.IBZ_SEC_DEGREE,
            QuatRepresentIntegerParamsLvl5.INSTANCE,
            QuatRepresentIntegerParamsLvl5.QUATALG_PINFTY,
            PrecompLvl5.QUAT_PRIMALITY_NUM_ITER,
            PrecompLvl5.QUAT_EQUIV_BOUND_COEFF,
            PrecompLvl5.TORSION_EVEN_POWER,
            PrecompLvl5.P_COFACTOR_FOR_2F.longValueExact(),
            Dim2Id2IsoLvl5::arbitraryIsogenyEvaluation,
            EcBasisLvl5::toHint,
            random);
        return new KeyPair(r.sk, r.hintPk);
    }
}
