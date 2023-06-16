package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum WireFormat
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short) 0),
    mls_public_message((short) 1),
    mls_private_message((short) 2),
    mls_welcome((short) 3),
    mls_group_info((short) 4),
    mls_key_package((short) 5);

    final short value;

    WireFormat(short value)
    {
        this.value = value;
    }

//    WireFormat(MLSInputStream stream) throws IOException
//    {
//        this.value = (short) stream.read(short.class);
//    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
