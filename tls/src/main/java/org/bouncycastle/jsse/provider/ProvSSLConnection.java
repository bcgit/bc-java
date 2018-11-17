package org.bouncycastle.jsse.provider;

import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.SecurityParameters;
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

    public String getApplicationProtocol()
    {
        SecurityParameters sp = tlsContext.getSecurityParametersConnection();
        if (null != sp)
        {
            ProtocolName applicationProtocol = sp.getApplicationProtocol();
            if (null != applicationProtocol)
            {
                return applicationProtocol.getUtf8Decoding();
            }
        }

        return "";
    }

    public byte[] getChannelBinding(String channelBinding)
    {
        if (channelBinding.equals("tls-server-end-point"))
        {
            return tlsContext.exportChannelBinding(ChannelBinding.tls_server_end_point);
        }

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
