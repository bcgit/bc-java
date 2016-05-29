package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsSecret implements TlsSecret
{
    protected byte[] data;

    public BcTlsSecret(byte[] data)
    {
        this.data = data;
    }

    public void export(OutputStream output) throws IOException
    {
        output.write(data);
    }
}
