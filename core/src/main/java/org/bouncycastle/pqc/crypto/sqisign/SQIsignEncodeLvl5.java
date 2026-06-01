package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Lvl5 driver for the shared {@link SQIsignEncode} engine.
 *
 * <p>For lvl5: {@code PUBLICKEY_BYTES = 129}, {@code SECRETKEY_BYTES = 701},
 * {@code FP_ENCODED_BYTES = 64}, {@code FP2_ENCODED_BYTES = 128},
 * {@code TORSION_2POWER_BYTES = 63}, {@code SIGNATURE_BYTES = 292}.</p>
 */
final class SQIsignEncodeLvl5
{
    public static final int FP_ENCODED_BYTES = 64;
    public static final int TORSION_2POWER_BYTES = 63;
    public static final int PUBLICKEY_BYTES = 129;
    public static final int SECRETKEY_BYTES = 701;
    public static final int SIGNATURE_BYTES = 292;
    public static final int RESPONSE_MAT_ENTRY_BYTES = 32;
    public static final int CHALL_COEFF_BYTES = 32;

    private static final SQIsignEncode.Params PARAMS = new SQIsignEncode.Params(
        GfFieldLvl5.INSTANCE,
        FP_ENCODED_BYTES, TORSION_2POWER_BYTES,
        PUBLICKEY_BYTES, SECRETKEY_BYTES,
        SIGNATURE_BYTES,
        RESPONSE_MAT_ENTRY_BYTES, CHALL_COEFF_BYTES,
        PrecompLvl5.TORSION_EVEN_POWER,
        ExtremalOrdersLvl5.MAXORD_O0,
        QuatRepresentIntegerParamsLvl5.QUATALG_PINFTY,
        new SQIsignEncode.FromHint()
        {
            public int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint)
            {
                return EcBasisLvl5.fromHint(basis, curve, torsionEvenPower, hint);
            }
        });

    private SQIsignEncodeLvl5()
    {
    }

    public static byte[] publicKeyToBytes(SQIsignPublicKeyData pk)
    {
        return SQIsignEncode.publicKeyToBytes(PARAMS, pk);
    }

    public static SQIsignPublicKeyData publicKeyFromBytes(byte[] enc)
    {
        return SQIsignEncode.publicKeyFromBytes(PARAMS, enc, 0);
    }

    public static byte[] secretKeyToBytes(SQIsignSecretKeyData sk, SQIsignPublicKeyData pk,
                                          QuatAlg algebra)
    {
        return SQIsignEncode.secretKeyToBytes(PARAMS, sk, pk, algebra);
    }

    public static SQIsignSecretKeyData secretKeyFromBytesFull(byte[] enc, int off,
                                                              SQIsignPublicKeyData pkOut)
    {
        return SQIsignEncode.secretKeyFromBytesFull(PARAMS, enc, off, pkOut);
    }

    public static byte[] signatureToBytes(SQIsignSignatureLvl5 sig)
    {
        return SQIsignEncode.signatureToBytes(PARAMS, sig);
    }

    public static SQIsignSignatureLvl5 signatureFromBytes(byte[] enc)
    {
        SQIsignSignatureLvl5 sig = new SQIsignSignatureLvl5();
        SQIsignEncode.signatureFromBytes(PARAMS, sig, enc, 0);
        return sig;
    }
}
