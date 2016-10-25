package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.tls.crypto.TlsHash;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(TlsHash d)
    {
        d.update(this.buf, 0, count);
    }
}
