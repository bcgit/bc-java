package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum ResumptionPSKUsage
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte)0),
    APPLICATION((byte)1),
    REINIT((byte)2),
    BRANCH((byte)3);

    final byte value;

    ResumptionPSKUsage(byte value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ResumptionPSKUsage(MLSInputStream stream)
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
