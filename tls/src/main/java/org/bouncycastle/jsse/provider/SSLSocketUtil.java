package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLSocket;

abstract class SSLSocketUtil
{
    private static final Method getHandshakeSession;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLSocket");

        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
    }

    static BCExtendedSSLSession importHandshakeSession(SSLSocket sslSocket)
    {
        if (sslSocket instanceof BCSSLSocket)
        {
            return ((BCSSLSocket)sslSocket).getBCHandshakeSession();
        }
        if (null != sslSocket && null != getHandshakeSession)
        {
            try
            {
                SSLSession sslSession = (SSLSession)ReflectionUtil.invokeGetter(sslSocket, getHandshakeSession);
                if (null != sslSession)
                {
                    return SSLSessionUtil.importSSLSession(sslSession);
                }
            }
            catch (Exception e)
            {
            }
        }
        return null;
    }
}
