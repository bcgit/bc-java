package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

public enum LeafNodeSource
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte)0),
    KEY_PACKAGE((byte)1),
    UPDATE((byte)2),
    COMMIT((byte)3);

    final byte value;

    LeafNodeSource(byte value)
    {
        this.value = value;
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(value);
    }
}
