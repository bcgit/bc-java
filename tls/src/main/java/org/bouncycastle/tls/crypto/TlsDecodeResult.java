package org.bouncycastle.tls.crypto;

public final class TlsDecodeResult
{
    public final byte[] buf;
    public final int off, len;
    public final short contentType;

    public TlsDecodeResult(byte[] buf, int off, int len, short contentType)
    {
        this.buf = buf;
        this.off = off;
        this.len = len;
        this.contentType = contentType;
    }
}
