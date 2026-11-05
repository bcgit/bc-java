package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;

import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Arrays;

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

    /**
     * A copy of this message (from its mark to its end) over a fresh buffer, for holding beyond the
     * lifetime of the record buffer this one may be a view of.
     */
    HandshakeMessageInput copy()
    {
        return new HandshakeMessageInput(Arrays.copyOfRange(buf, mark, count), 0, count - mark);
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
