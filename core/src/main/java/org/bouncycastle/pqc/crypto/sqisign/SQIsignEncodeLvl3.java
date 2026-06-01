package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Lvl3 driver for the shared {@link SQIsignEncode} engine.
 *
 * <p>For lvl3: {@code PUBLICKEY_BYTES = 97}, {@code SECRETKEY_BYTES = 529},
 * {@code FP_ENCODED_BYTES = 48}, {@code FP2_ENCODED_BYTES = 96},
 * {@code TORSION_2POWER_BYTES = 48}, {@code SIGNATURE_BYTES = 224}.</p>
 */
final class SQIsignEncodeLvl3
{
    public static final int FP_ENCODED_BYTES = 48;
    public static final int TORSION_2POWER_BYTES = 48;
    public static final int PUBLICKEY_BYTES = 97;
    public static final int SECRETKEY_BYTES = 529;
    public static final int SIGNATURE_BYTES = 224;
    public static final int RESPONSE_MAT_ENTRY_BYTES = 25;
    public static final int CHALL_COEFF_BYTES = 24;

    private static final SQIsignEncode.Params PARAMS = new SQIsignEncode.Params(
        GfFieldLvl3.INSTANCE,
        FP_ENCODED_BYTES, TORSION_2POWER_BYTES,
        PUBLICKEY_BYTES, SECRETKEY_BYTES,
        SIGNATURE_BYTES,
        RESPONSE_MAT_ENTRY_BYTES, CHALL_COEFF_BYTES,
        PrecompLvl3.TORSION_EVEN_POWER,
        ExtremalOrdersLvl3.MAXORD_O0,
        QuatRepresentIntegerParamsLvl3.QUATALG_PINFTY,
        new SQIsignEncode.FromHint()
        {
            public int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint)
            {
                return EcBasisLvl3.fromHint(basis, curve, torsionEvenPower, hint);
            }
        });

    private SQIsignEncodeLvl3()
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

    public static byte[] signatureToBytes(SQIsignSignatureLvl3 sig)
    {
        return SQIsignEncode.signatureToBytes(PARAMS, sig);
    }

    public static SQIsignSignatureLvl3 signatureFromBytes(byte[] enc)
    {
        SQIsignSignatureLvl3 sig = new SQIsignSignatureLvl3();
        SQIsignEncode.signatureFromBytes(PARAMS, sig, enc, 0);
        return sig;
    }
}
