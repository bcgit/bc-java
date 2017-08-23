package org.bouncycastle.jsse.provider;

import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.TlsContext;

class ProvSSLConnection
    implements BCSSLConnection
{
    protected final TlsContext tlsContext;
    protected final ProvSSLSessionImpl sessionImpl; 

    ProvSSLConnection(TlsContext tlsContext, ProvSSLSessionImpl sessionImpl)
    {
        this.tlsContext = tlsContext;
        this.sessionImpl = sessionImpl;
    }

    ProvSSLSessionImpl getSessionImpl()
    {
        return sessionImpl;
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
        return sessionImpl.getExportSession();
    }
}
