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
    private static final boolean useEngine8;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLEngine");

        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
        getSSLParameters = ReflectionUtil.findMethod(methods, "getSSLParameters");

        // Note that we only need this for the 8u251 update with ALPN methods
        useEngine8 = ReflectionUtil.hasMethod(methods, "getApplicationProtocol");
    }

    static SSLEngine create(ContextData contextData)
    {
        return useEngine8
            ?   new ProvSSLEngine_8(contextData)
            :   new ProvSSLEngine(contextData);
    }

    static SSLEngine create(ContextData contextData, String host, int port)
    {
        return useEngine8
            ?   new ProvSSLEngine_8(contextData, host, port)
            :   new ProvSSLEngine(contextData, host, port);
    }

    static BCExtendedSSLSession importHandshakeSession(SSLEngine sslEngine)
    {
        if (sslEngine instanceof BCSSLEngine)
        {
            return ((BCSSLEngine)sslEngine).getBCHandshakeSession();
        }
        if (null != sslEngine && null != getHandshakeSession)
        {
            SSLSession sslSession = (SSLSession)ReflectionUtil.invokeGetter(sslEngine, getHandshakeSession);
            if (null != sslSession)
            {
                return SSLSessionUtil.importSSLSession(sslSession);
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
        if (null == sslEngine || null == getSSLParameters)
        {
            return null;
        }

        SSLParameters sslParameters = (SSLParameters)ReflectionUtil.invokeGetter(sslEngine, getSSLParameters);
        if (null == sslParameters)
        {
            throw new RuntimeException("SSLEngine.getSSLParameters returned null");
        }

        return SSLParametersUtil.importSSLParameters(sslParameters);
    }
}
