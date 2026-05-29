package org.bouncycastle.pqc.crypto.sqisign;

/**
 * SQIsign level-3 signature: 224 bytes when encoded (96-byte E_aux_A
 * fp2 blob + 2 length bytes + 4×25-byte matrix entries + 24-byte
 * chall_coeff + 2 hint bytes). See {@link SQIsignSignature} for the
 * shared in-memory layout.
 */
final class SQIsignSignatureLvl3
    extends SQIsignSignature
{
    public SQIsignSignatureLvl3()
    {
        super();
    }
}
