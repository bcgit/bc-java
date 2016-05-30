package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsSecret implements TlsSecret
{
    protected byte[] data;

    public BcTlsSecret(byte[] data)
    {
        this.data = data;
    }

    public synchronized byte[] extract()
    {
        byte[] result = data;
        this.data = null;
        return result;
    }
}
