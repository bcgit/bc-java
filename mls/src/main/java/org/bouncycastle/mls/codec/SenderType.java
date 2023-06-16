package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum SenderType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte) 0),
    MEMBER((byte) 1),
    EXTERNAL((byte) 2),
    NEW_MEMBER_PROPOSAL((byte) 3),
    NEW_MEMBER_COMMIT((byte) 4);

    final byte value;

    SenderType(byte value)
    {
        this.value = value;
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
