package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLEngine;

abstract class SSLEngineUtil
{
    private static final Method getHandshakeSession;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLEngine");

        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
    }

    static BCExtendedSSLSession importHandshakeSession(SSLEngine sslEngine)
    {
        if (sslEngine instanceof BCSSLEngine)
        {
            return ((BCSSLEngine)sslEngine).getBCHandshakeSession();
        }
        if (null != sslEngine && null != getHandshakeSession)
        {
            try
            {
                SSLSession sslSession = (SSLSession)ReflectionUtil.invokeGetter(sslEngine, getHandshakeSession);
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
