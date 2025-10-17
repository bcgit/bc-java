package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;

abstract class SSLSessionUtil
{
    private static final Class<?> extendedSSLSessionClass;
    private static final Constructor<? extends SSLSession> exportSSLSessionConstructor;
    private static final Constructor<? extends BCExtendedSSLSession> importSSLSessionConstructor;

    static
    {
        {
            Class<?> clazz = null;
            try
            {
                clazz = ReflectionUtil.getClass("javax.net.ssl.ExtendedSSLSession");
            }
            catch (Exception e)
            {
            }
            extendedSSLSessionClass = clazz;
        }

        {
            Constructor<? extends SSLSession> constructor = null;
            try
            {
                Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.ExtendedSSLSession");
                if (null != methods)
                {
                    String className;
                    if (ReflectionUtil.hasMethod(methods, "getRequestedServerNames"))
                    {
                        className = "org.bouncycastle.jsse.provider.ExportSSLSession_8";
                    }
                    else
                    {
                        className = "org.bouncycastle.jsse.provider.ExportSSLSession_7";
                    }

                    constructor = ReflectionUtil.getDeclaredConstructor(className, BCExtendedSSLSession.class);
                }
            }
            catch (Exception e)
            {
            }

            exportSSLSessionConstructor = constructor;
        }

        {
            Constructor<? extends BCExtendedSSLSession> constructor = null;
            if (null != extendedSSLSessionClass)
            {
                try
                {
                    Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.ExtendedSSLSession");
                    if (null != methods)
                    {
                        String className;
                        if (ReflectionUtil.hasMethod(methods, "getRequestedServerNames"))
                        {
                            className = "org.bouncycastle.jsse.provider.ImportSSLSession_8";
                        }
                        else
                        {
                            className = "org.bouncycastle.jsse.provider.ImportSSLSession_7";
                        }

                        constructor = ReflectionUtil.getDeclaredConstructor(className, extendedSSLSessionClass);
                    }
                }
                catch (Exception e)
                {
                }
            }
            importSSLSessionConstructor = constructor;
        }
    }

    static SSLSession exportSSLSession(BCExtendedSSLSession sslSession)
    {
        if (sslSession instanceof ImportSSLSession)
        {
            return ((ImportSSLSession)sslSession).unwrap();
        }

        if (null != exportSSLSessionConstructor)
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

        if (null != importSSLSessionConstructor && extendedSSLSessionClass.isInstance(sslSession))
        {
            try
            {
                return importSSLSessionConstructor.newInstance(sslSession);
            }
            catch (Exception e)
            {
            }
        }

        return new ImportSSLSession_5(sslSession);
    }
}
