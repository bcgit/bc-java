package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;


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
            BigIntegers.longValueExact(PrecompLvl3.P_COFACTOR_FOR_2F),
            new SQIsignKeyGen.IdealToIsogeny()
            {
                public int arbitraryIsogenyEvaluation(EcBasis canonicalBasis, EcCurve codomain,
                                                      QuatLeftIdeal lideal, SecureRandom rnd)
                {
                    return Dim2Id2IsoLvl3.arbitraryIsogenyEvaluation(canonicalBasis, codomain, lideal, rnd);
                }
            },
            new SQIsignKeyGen.ToHint()
            {
                public int toHint(EcBasis basis, EcCurve curve, int torsionEvenPower)
                {
                    return EcBasisLvl3.toHint(basis, curve, torsionEvenPower);
                }
            },
            random);
        return new KeyPair(r.sk, r.hintPk);
    }
}
