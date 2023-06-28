package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum ProposalType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short) 0),
    ADD((short) 1),
    UPDATE((short) 2),
    REMOVE((short) 3),
    PSK((short) 4),
    REINIT((short) 5),
    EXTERNAL_INIT((short) 6),
    GROUP_CONTEXT_EXTENSIONS((short) 7);
    final short value;

    ProposalType(short value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ProposalType(MLSInputStream stream) throws IOException
    {
        this.value = (short) stream.read(short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
