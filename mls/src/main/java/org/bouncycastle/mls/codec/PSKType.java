package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum PSKType
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    REFERENCE((byte)0),
    EXTERNAL((byte)1),
    RESUMPTION((byte)2);

    final byte value;

    PSKType(byte value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    PSKType(MLSInputStream stream)
        throws IOException
    {
        this.value = (byte)stream.read(byte.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(value);
    }
}
