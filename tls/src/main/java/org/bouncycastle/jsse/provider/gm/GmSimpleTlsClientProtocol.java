package org.bouncycastle.jsse.provider.gm;


import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsClientProtocol;

import java.io.InputStream;
import java.io.OutputStream;

public class GmSimpleTlsClientProtocol extends TlsClientProtocol implements SecurityParameterProvider
{
    public GmSimpleTlsClientProtocol()
    {
    }

    public GmSimpleTlsClientProtocol(InputStream input, OutputStream output)
    {
        super(input, output);
    }

    public SecurityParameters getSecurityParameters()
    {
        return super.getContext().getSecurityParameters();
    }
}
