package org.bouncycastle.jsse.provider;

import java.util.List;

class ProvExtendedSSLSession_9
    extends ProvExtendedSSLSession_8
{
    ProvExtendedSSLSession_9(ProvSSLSession sslSession)
    {
        super(sslSession);
    }

    public List<byte[]> getStatusResponses()
    {
        return sslSession.getStatusResponses();
    }
}
