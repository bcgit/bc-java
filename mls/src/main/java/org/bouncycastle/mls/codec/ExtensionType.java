package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum ExtensionType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short) 0),
    APPLICATION_ID((short) 1),
    RATCHET_TREE((short) 2),
    REQUIRED_CAPABILITIES((short) 3),
    EXTERNAL_PUB((short) 4),
    EXTERNAL_SENDERS((short) 5);
    final short value;

    ExtensionType(short value)
    {
        this.value = value;
    }


    ExtensionType(MLSInputStream stream) throws IOException
    {
        this.value = (short) stream.read(short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }

    public short getValue()
    {
        return value;
    }
}
