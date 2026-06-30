package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;


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
            BigIntegers.longValueExact(PrecompLvl5.P_COFACTOR_FOR_2F),
            new SQIsignKeyGen.IdealToIsogeny()
            {
                public int arbitraryIsogenyEvaluation(EcBasis canonicalBasis, EcCurve codomain,
                                                      QuatLeftIdeal lideal, SecureRandom rnd)
                {
                    return Dim2Id2IsoLvl5.arbitraryIsogenyEvaluation(canonicalBasis, codomain, lideal, rnd);
                }
            },
            new SQIsignKeyGen.ToHint()
            {
                public int toHint(EcBasis basis, EcCurve curve, int torsionEvenPower)
                {
                    return EcBasisLvl5.toHint(basis, curve, torsionEvenPower);
                }
            },
            random);
        return new KeyPair(r.sk, r.hintPk);
    }
}
