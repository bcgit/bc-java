package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

abstract class SSLSocketUtil
{
    private static final Method getHandshakeSession;
    private static final Method getSSLParameters;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLSocket");

        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
        getSSLParameters = ReflectionUtil.findMethod(methods, "getSSLParameters");
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

    static BCSSLParameters importSSLParameters(SSLSocket sslSocket)
    {
        if (sslSocket instanceof BCSSLSocket)
        {
            return ((BCSSLSocket)sslSocket).getParameters();
        }
        if (null != sslSocket && null != getSSLParameters)
        {
            try
            {
                SSLParameters sslParameters = (SSLParameters)ReflectionUtil.invokeGetter(sslSocket, getSSLParameters);
                if (null != sslParameters)
                {
                    return SSLParametersUtil.importSSLParameters(sslParameters);
                }
            }
            catch (Exception e)
            {
            }
        }
        return null;
    }
}
