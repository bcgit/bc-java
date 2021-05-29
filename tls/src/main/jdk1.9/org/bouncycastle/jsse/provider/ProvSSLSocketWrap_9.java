package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

class ProvSSLSocketWrap_9
    extends ProvSSLSocketWrap_8
{
    protected ProvSSLSocketWrap_9(ContextData contextData, Socket s, InputStream consumed, boolean autoClose)
        throws IOException
    {
        super(contextData, s, consumed, autoClose);
    }

    protected ProvSSLSocketWrap_9(ContextData contextData, Socket s, String host, int port, boolean autoClose)
        throws IOException
    {
        super(contextData, s, host, port, autoClose);
    }
}
