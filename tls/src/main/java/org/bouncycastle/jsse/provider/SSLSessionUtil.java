package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;

abstract class SSLSessionUtil
{
    private static final Constructor<? extends SSLSession> exportSSLSessionConstructor;

    static
    {
        Constructor<? extends SSLSession> cons = null;
        try
        {
            Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.ExtendedSSLSession");
            if (null != methods)
            {
                String className;
                if (ReflectionUtil.hasMethod(methods, "getStatusResponses"))
                {
                    className = "org.bouncycastle.jsse.provider.ExportSSLSession_9";
                }
                else if (ReflectionUtil.hasMethod(methods, "getRequestedServerNames"))
                {
                    className = "org.bouncycastle.jsse.provider.ExportSSLSession_8";
                }
                else
                {
                    className = "org.bouncycastle.jsse.provider.ExportSSLSession_7";
                }

                cons = ReflectionUtil.getDeclaredConstructor(className, BCExtendedSSLSession.class);
            }
        }
        catch (Exception e)
        {
        }

        exportSSLSessionConstructor = cons;
    }

    static SSLSession exportSSLSession(BCExtendedSSLSession sslSession)
    {
        if (exportSSLSessionConstructor != null)
        {
            try
            {
                return exportSSLSessionConstructor.newInstance(sslSession);
            }
            catch (Exception e)
            {
            }
        }

        return new ExportSSLSession_5(sslSession);
    }
}
