package org.bouncycastle.pqc.crypto.sqisign;

/**
 * SQIsign level-1 signature: 148 bytes when encoded (64-byte E_aux_A
 * fp2 blob + 2 length bytes + 4×16-byte matrix entries + 16-byte
 * chall_coeff + 2 hint bytes). See {@link SQIsignSignature} for the
 * shared in-memory layout.
 */
final class SQIsignSignatureLvl1
    extends SQIsignSignature
{
    public SQIsignSignatureLvl1()
    {
        super();
    }
}
