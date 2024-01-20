package org.bouncycastle.mls.codec;

import java.io.IOException;

public class Certificate
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] cert_data;

    Certificate(MLSInputStream stream) throws IOException
    {
        cert_data = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.writeOpaque(cert_data);
    }
}
