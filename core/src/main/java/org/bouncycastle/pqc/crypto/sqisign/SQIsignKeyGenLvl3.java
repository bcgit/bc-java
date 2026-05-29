package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;


/**
 * Lvl3 driver for the shared {@link SQIsignKeyGen} engine.
 */
final class SQIsignKeyGenLvl3
{
    private SQIsignKeyGenLvl3()
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
            PrecompLvl3.IBZ_SEC_DEGREE,
            QuatRepresentIntegerParamsLvl3.INSTANCE,
            QuatRepresentIntegerParamsLvl3.QUATALG_PINFTY,
            PrecompLvl3.QUAT_PRIMALITY_NUM_ITER,
            PrecompLvl3.QUAT_EQUIV_BOUND_COEFF,
            PrecompLvl3.TORSION_EVEN_POWER,
            PrecompLvl3.P_COFACTOR_FOR_2F.longValueExact(),
            Dim2Id2IsoLvl3::arbitraryIsogenyEvaluation,
            EcBasisLvl3::toHint,
            random);
        return new KeyPair(r.sk, r.hintPk);
    }
}
