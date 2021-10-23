package org.bouncycastle.jsse.provider.gm;


import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsServerProtocol;

import java.io.InputStream;
import java.io.OutputStream;

public class GmSimpleTlsServerProtocol  extends TlsServerProtocol implements SecurityParameterProvider
{
    public GmSimpleTlsServerProtocol()
    {
    }

    public GmSimpleTlsServerProtocol(InputStream input, OutputStream output)
    {
        super(input, output);
    }

    public SecurityParameters getSecurityParameters()
    {
        return super.getContext().getSecurityParameters();
    }
}
