package org.bouncycastle.jsse.provider;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsContext;

class ProvSSLConnection
    implements BCSSLConnection
{
    protected final TlsContext tlsContext;
    protected final ProvSSLSession session; 

    ProvSSLConnection(TlsContext tlsContext, ProvSSLSession session)
    {
        this.tlsContext = tlsContext;
        this.session = session;
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

    public ProvSSLSession getSession()
    {
        return session;
    }
}
