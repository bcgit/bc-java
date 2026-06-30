package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;


/**
 * Lvl1 driver for the shared {@link SQIsignKeyGen} engine. Wires the lvl1
 * precomp constants and the lvl1 {@code Dim2Id2IsoLvl1.arbitraryIsogenyEvaluation}
 * / {@code EcBasisLvl1.toHint} callbacks into the level-independent core.
 */
final class SQIsignKeyGenLvl1
{
    private SQIsignKeyGenLvl1()
    {
    }

    /** Bundle of outputs from {@link #protocolsKeygenFull}. */
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
            PrecompLvl1.IBZ_SEC_DEGREE,
            QuatRepresentIntegerParamsLvl1.INSTANCE,
            PrecompLvl1.QUATALG_PINFTY,
            PrecompLvl1.QUAT_PRIMALITY_NUM_ITER,
            PrecompLvl1.QUAT_EQUIV_BOUND_COEFF,
            PrecompLvl1.TORSION_EVEN_POWER,
            BigIntegers.longValueExact(PrecompLvl1.P_COFACTOR_FOR_2F),
            new SQIsignKeyGen.IdealToIsogeny()
            {
                public int arbitraryIsogenyEvaluation(EcBasis canonicalBasis, EcCurve codomain,
                                                      QuatLeftIdeal lideal, SecureRandom rnd)
                {
                    return Dim2Id2IsoLvl1.arbitraryIsogenyEvaluation(canonicalBasis, codomain, lideal, rnd);
                }
            },
            new SQIsignKeyGen.ToHint()
            {
                public int toHint(EcBasis basis, EcCurve curve, int torsionEvenPower)
                {
                    return EcBasisLvl1.toHint(basis, curve, torsionEvenPower);
                }
            },
            random);
        return new KeyPair(r.sk, r.hintPk);
    }
}
