package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Structured SQIsign public key: the public curve (normalized A coefficient)
 * plus a hint byte for fast 2^f-basis recomputation during verification.
 * Mirrors C {@code public_key_t}.
 */
final class SQIsignPublicKeyData
{
    public final EcCurve curve;
    public int hintPk;

    public SQIsignPublicKeyData()
    {
        this.curve = new EcCurve();
        this.hintPk = 0;
    }
}
