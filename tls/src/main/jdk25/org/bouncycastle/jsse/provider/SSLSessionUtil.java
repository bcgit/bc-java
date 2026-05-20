package org.bouncycastle.jsse.provider;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;

abstract class SSLSessionUtil
{
    static SSLSession exportSSLSession(BCExtendedSSLSession sslSession)
    {
        if (sslSession instanceof ImportSSLSession importSSLSession)
        {
            return importSSLSession.unwrap();
        }

        return new ExportSSLSession_25(sslSession);
    }

    static BCExtendedSSLSession importSSLSession(SSLSession sslSession)
    {
        if (sslSession instanceof BCExtendedSSLSession bcExtendedSSLSession)
        {
            return bcExtendedSSLSession;
        }

        if (sslSession instanceof ExportSSLSession exportSSLSession)
        {
            return exportSSLSession.unwrap();
        }

        if (sslSession instanceof ExtendedSSLSession extendedSSLSession)
        {
            return new ImportSSLSession_25(extendedSSLSession);
        }

        return new ImportSSLSession_5(sslSession);
    }
}
