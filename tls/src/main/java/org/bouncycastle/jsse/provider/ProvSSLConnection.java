package org.bouncycastle.jsse.provider;

import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.TlsContext;

class ProvSSLConnection
    implements BCSSLConnection
{
    protected final TlsContext tlsContext;
    protected final SSLSession session; 

    ProvSSLConnection(TlsContext tlsContext, SSLSession session)
    {
        this.tlsContext = tlsContext;
        this.session = session;
    }

    public byte[] getChannelBinding(String channelBinding)
    {
        if (channelBinding.equals("tls-unique"))
        {
            return tlsContext.exportChannelBinding(ChannelBinding.tls_unique);
        }

        throw new UnsupportedOperationException();
    }

    public SSLSession getSession()
    {
        return session;
    }
}
