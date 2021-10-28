package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;

import org.bouncycastle.tls.crypto.TlsHash;

public class HandshakeMessageInput
    extends ByteArrayInputStream
{
    HandshakeMessageInput(byte[] buf, int offset, int length)
    {
        super(buf, offset, length);
    }

    public boolean markSupported()
    {
        return false;
    }

    public void mark(int readAheadLimit)
    {
        throw new UnsupportedOperationException();
    }

    public void updateHash(TlsHash hash)
    {
        hash.update(buf, mark, count - mark);
    }

    void updateHashPrefix(TlsHash hash, int bindersSize)
    {
        hash.update(buf, mark, count - mark - bindersSize);
    }

    void updateHashSuffix(TlsHash hash, int bindersSize)
    {
        hash.update(buf, count - bindersSize, bindersSize);
    }
}
