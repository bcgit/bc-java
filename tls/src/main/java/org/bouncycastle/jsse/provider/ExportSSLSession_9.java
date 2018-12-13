package org.bouncycastle.jsse.provider;

import java.util.List;

class ExportSSLSession_9
    extends ExportSSLSession_8
{
    ExportSSLSession_9(ProvSSLSession sslSession)
    {
        super(sslSession);
    }

    public List<byte[]> getStatusResponses()
    {
        return sslSession.getStatusResponses();
    }
}
