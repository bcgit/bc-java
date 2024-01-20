package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum ContentType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte) 0),
    APPLICATION((byte) 1),
    PROPOSAL((byte) 2),
    COMMIT((byte) 3);

    final byte value;

    ContentType(byte value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ContentType(MLSInputStream stream) throws IOException
    {
        this.value = (byte) stream.read(byte.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
