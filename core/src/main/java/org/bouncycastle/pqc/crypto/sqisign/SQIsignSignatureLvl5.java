package org.bouncycastle.pqc.crypto.sqisign;

/**
 * SQIsign level-5 signature: 292 bytes when encoded (128-byte E_aux_A
 * fp2 blob + 2 length bytes + 4×32-byte matrix entries + 32-byte
 * chall_coeff + 2 hint bytes). See {@link SQIsignSignature} for the
 * shared in-memory layout.
 */
final class SQIsignSignatureLvl5
    extends SQIsignSignature
{
    public SQIsignSignatureLvl5()
    {
        super();
    }
}
