package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum NodeType
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte)0),
    leaf((byte)1),
    parent((byte)2);

    final byte value;

    NodeType(byte value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    NodeType(MLSInputStream stream)
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

    public static NodeType fromValue(byte value)
    {
        for (NodeType element : values())
        {
            if (element.value == value)
            {
                return element;
            }
        }

        throw new IllegalArgumentException("unknown NodeType value: " + value);
    }
}
