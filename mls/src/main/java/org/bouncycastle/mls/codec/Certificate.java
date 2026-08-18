package org.bouncycastle.mls.codec;

import java.io.IOException;

public class Certificate
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    byte[] cert_data;

    Certificate(MLSInputStream stream)
        throws IOException
    {
        cert_data = stream.readOpaque();
    }

    /**
     * @param certData the DER encoding of a single X.509 certificate in the credential's chain.
     */
    public Certificate(byte[] certData)
    {
        this.cert_data = certData;
    }

    public byte[] getCertData()
    {
        return cert_data;
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.writeOpaque(cert_data);
    }
}
