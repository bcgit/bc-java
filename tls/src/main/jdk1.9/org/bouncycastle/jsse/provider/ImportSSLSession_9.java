package org.bouncycastle.jsse.provider;

import java.util.List;

import javax.net.ssl.ExtendedSSLSession;

class ImportSSLSession_9
    extends ImportSSLSession_8
{
    ImportSSLSession_9(ExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    @Override
    public List<byte[]> getStatusResponses()
    {
        return sslSession.getStatusResponses();
    }
}
