package org.bouncycastle.crypto.hpke;

import org.bouncycastle.util.Arrays;

public class Context
{

    public AEAD aead;
    private final HKDF hkdf;
    private final byte[] exporterSecret;
    private final byte[] suiteId;
    protected byte[] enc;

    Context(AEAD aead, HKDF hkdf, byte[] exporterSecret, byte[] suiteId)
    {
        this.aead = aead;
        this.hkdf = hkdf;
        this.exporterSecret = exporterSecret;
        this.suiteId = suiteId;
    }

    public byte[] Export(byte[] exportContext, int L)
            throws Exception
    {
        return hkdf.LabeledExpand(exporterSecret, suiteId, "sec", exportContext, L);
    }

    protected void SetEnc(byte[] enc)
    {
        this.enc = enc;
    }

    public byte[] getEnc()
    {
        return Arrays.clone(this.enc);
    }

}
