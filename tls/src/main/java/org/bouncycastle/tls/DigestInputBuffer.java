package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(TlsHash d)
    {
        d.update(this.buf, 0, count);
    }
}
