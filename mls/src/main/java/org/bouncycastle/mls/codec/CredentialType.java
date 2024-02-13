package org.bouncycastle.mls.codec;

import java.io.IOException;

public enum CredentialType
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    RESERVED((short)0),
    basic((short)1),
    x509((short)2),
    GREASE_0((short)0x0A0A),
    GREASE_1((short)0x1A1A),
    GREASE_2((short)0x2A2A),
    GREASE_3((short)0x3A3A),
    GREASE_4((short)0x4A4A),
    GREASE_5((short)0x5A5A),
    GREASE_6((short)0x6A6A),
    GREASE_7((short)0x7A7A),
    GREASE_8((short)0x8A8A),
    GREASE_9((short)0x9A9A),
    GREASE_A((short)0xAAAA),
    GREASE_B((short)0xBABA),
    GREASE_C((short)0xCACA),
    GREASE_D((short)0xDADA),
    GREASE_E((short)0xEAEA);

    final short value;

    CredentialType(short value)
    {
        this.value = value;
    }

    @SuppressWarnings("unused")
    CredentialType(MLSInputStream stream)
        throws IOException
    {
        this.value = (short)stream.read(short.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(value);
    }
}
