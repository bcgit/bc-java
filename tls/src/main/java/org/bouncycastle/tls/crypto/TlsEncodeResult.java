package org.bouncycastle.tls.crypto;

public final class TlsEncodeResult
{
    public final byte[] buf;
    public final int off, len;
    public final short recordType;

    public TlsEncodeResult(byte[] buf, int off, int len, short recordType)
    {
        this.buf = buf;
        this.off = off;
        this.len = len;
        this.recordType = recordType;
    }
}
