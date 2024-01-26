package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum ProposalOrRefType
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((byte)0),
    PROPOSAL((byte)1),
    REFERENCE((byte)2);

    final byte value;

    ProposalOrRefType(byte value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ProposalOrRefType(MLSInputStream stream)
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
