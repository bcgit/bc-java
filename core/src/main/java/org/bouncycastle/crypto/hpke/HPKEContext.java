package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.InvalidCipherTextException;

public class HPKEContext
{
    protected final AEAD aead;
    protected final HKDF hkdf;
    protected final byte[] exporterSecret;
    protected final byte[] suiteId;

    HPKEContext(AEAD aead, HKDF hkdf, byte[] exporterSecret, byte[] suiteId)
    {
        this.aead = aead;
        this.hkdf = hkdf;
        this.exporterSecret = exporterSecret;
        this.suiteId = suiteId;
    }

    public byte[] export(byte[] exportContext, int L)
    {
        return hkdf.LabeledExpand(exporterSecret, suiteId, "sec", exportContext, L);
    }

    public byte[] seal(byte[] aad, byte[] message)
        throws InvalidCipherTextException
    {
        return aead.seal(aad, message);
    }

    public byte[] seal(byte[] aad, byte[] pt, int ptOffset, int ptLength)
        throws InvalidCipherTextException
    {
        return aead.seal(aad, pt, ptOffset, ptLength);
    }

    public byte[] open(byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        return aead.open(aad, ct);
    }

    public byte[] open(byte[] aad, byte[] ct, int ctOffset, int ctLength)
        throws InvalidCipherTextException
    {
        return aead.open(aad, ct, ctOffset, ctLength);
    }

    public byte[] extract(byte[] salt, byte[] ikm)
    {
        return hkdf.Extract(salt, ikm);
    }

    public byte[] expand(byte[] prk, byte[] info, int L)
    {
        return hkdf.Expand(prk, info, L);
    }
}
