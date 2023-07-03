package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum CredentialType
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short) 0),
    basic((short) 1),
    x509((short) 2);

    final short value;

    CredentialType(short value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    CredentialType(MLSInputStream stream) throws IOException
    {
        this.value = (short) stream.read(short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
