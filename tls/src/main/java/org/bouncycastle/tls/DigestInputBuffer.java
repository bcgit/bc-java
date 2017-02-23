package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.io.Streams;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(TlsHash d)
    {
        d.update(this.buf, 0, count);
    }

    void copyTo(OutputStream output) throws IOException
    {
        // NOTE: Copy data since the output here may be under control of external code.
        Streams.pipeAll(new ByteArrayInputStream(buf, 0, count), output);
    }
}
