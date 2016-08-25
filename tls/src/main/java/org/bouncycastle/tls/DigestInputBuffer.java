package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.Digest;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(TlsHash d)
    {
        d.update(this.buf, 0, count);
    }
     // TODO: eliminate
    void updateDigest(Digest d)
    {
        d.update(this.buf, 0, count);
    }
}
