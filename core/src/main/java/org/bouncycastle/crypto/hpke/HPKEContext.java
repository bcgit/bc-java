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

    public byte[] open(byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        return aead.open(aad, ct);
    }
}
