package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;

abstract class SSLEngineUtil
{
    private static final Method getHandshakeSession;
    private static final Method getSSLParameters;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLEngine");

        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
        getSSLParameters = ReflectionUtil.findMethod(methods, "getSSLParameters");
    }

    static SSLEngine create(ProvSSLContextSpi context, ContextData contextData)
    {
        return new ProvSSLEngine(context, contextData);
    }

    static SSLEngine create(ProvSSLContextSpi context, ContextData contextData, String host, int port)
    {
        return new ProvSSLEngine(context, contextData, host, port);
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

    static BCSSLParameters importSSLParameters(SSLEngine sslEngine)
    {
        if (sslEngine instanceof BCSSLEngine)
        {
            return ((BCSSLEngine)sslEngine).getParameters();
        }
        if (null != sslEngine && null != getSSLParameters)
        {
            try
            {
                SSLParameters sslParameters = (SSLParameters)ReflectionUtil.invokeGetter(sslEngine, getSSLParameters);
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
