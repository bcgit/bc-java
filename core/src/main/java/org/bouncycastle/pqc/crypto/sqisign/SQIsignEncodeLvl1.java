package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Lvl1 driver for the shared {@link SQIsignEncode} engine. Wires the lvl1
 * field instance, byte sizes, and {@code EcBasisLvl1::fromHint} callback into
 * the level-independent core.
 *
 * <p>For lvl1: {@code PUBLICKEY_BYTES = 65}, {@code SECRETKEY_BYTES = 353},
 * {@code FP_ENCODED_BYTES = 32}, {@code FP2_ENCODED_BYTES = 64},
 * {@code TORSION_2POWER_BYTES = 32}, {@code SIGNATURE_BYTES = 148}.</p>
 */
final class SQIsignEncodeLvl1
{
    public static final int FP_ENCODED_BYTES = 32;
    public static final int TORSION_2POWER_BYTES = 32;
    public static final int PUBLICKEY_BYTES = 65;
    public static final int SECRETKEY_BYTES = 353;
    public static final int SIGNATURE_BYTES = 148;
    public static final int RESPONSE_MAT_ENTRY_BYTES = 16;
    public static final int CHALL_COEFF_BYTES = 16;

    private static final SQIsignEncode.Params PARAMS = new SQIsignEncode.Params(
        GfFieldLvl1.INSTANCE,
        FP_ENCODED_BYTES, TORSION_2POWER_BYTES,
        PUBLICKEY_BYTES, SECRETKEY_BYTES,
        SIGNATURE_BYTES,
        RESPONSE_MAT_ENTRY_BYTES, CHALL_COEFF_BYTES,
        PrecompLvl1.TORSION_EVEN_POWER,
        ExtremalOrdersLvl1.MAXORD_O0,
        PrecompLvl1.QUATALG_PINFTY,
        new SQIsignEncode.FromHint()
        {
            public int fromHint(EcBasis basis, EcCurve curve, int torsionEvenPower, int hint)
            {
                return EcBasisLvl1.fromHint(basis, curve, torsionEvenPower, hint);
            }
        });

    private SQIsignEncodeLvl1()
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

    public static byte[] signatureToBytes(SQIsignSignatureLvl1 sig)
    {
        return SQIsignEncode.signatureToBytes(PARAMS, sig);
    }

    public static SQIsignSignatureLvl1 signatureFromBytes(byte[] enc)
    {
        SQIsignSignatureLvl1 sig = new SQIsignSignatureLvl1();
        SQIsignEncode.signatureFromBytes(PARAMS, sig, enc, 0);
        return sig;
    }
}
