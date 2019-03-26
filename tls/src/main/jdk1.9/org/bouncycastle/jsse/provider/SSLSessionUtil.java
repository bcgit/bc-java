package org.bouncycastle.jsse.provider;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;

abstract class SSLSessionUtil
{
    static SSLSession exportSSLSession(BCExtendedSSLSession sslSession)
    {
        if (sslSession instanceof ImportSSLSession)
        {
            return ((ImportSSLSession)sslSession).unwrap();
        }

        return new ExportSSLSession_9(sslSession);
    }

    static BCExtendedSSLSession importSSLSession(SSLSession sslSession)
    {
        if (sslSession instanceof BCExtendedSSLSession)
        {
            return (BCExtendedSSLSession)sslSession;
        }

        if (sslSession instanceof ExportSSLSession)
        {
            return ((ExportSSLSession)sslSession).unwrap();
        }

        if (sslSession instanceof ExtendedSSLSession)
        {
            return new ImportSSLSession_9((ExtendedSSLSession)sslSession);
        }

        return new ImportSSLSession_5(sslSession);
    }
}
