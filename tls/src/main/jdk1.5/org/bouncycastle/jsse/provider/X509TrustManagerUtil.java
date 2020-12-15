package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

abstract class X509TrustManagerUtil
{
    private static final Class<?> x509ExtendedTrustManagerClass;
    private static final Constructor<? extends X509TrustManager> exportX509TrustManagerConstructor;
    private static final Constructor<? extends BCX509ExtendedTrustManager> importX509TrustManagerConstructor;

    static
    {
        {
            Class<?> clazz = null;
            try
            {
                clazz = ReflectionUtil.getClass("javax.net.ssl.X509ExtendedTrustManager");
            }
            catch (Exception e)
            {
            }
            x509ExtendedTrustManagerClass = clazz;
        }

        {
            Constructor<? extends X509TrustManager> constructor = null;
            try
            {
                Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.X509ExtendedTrustManager");
                if (null != methods)
                {
                    String className = "org.bouncycastle.jsse.provider.ExportX509TrustManager_7";

                    constructor = ReflectionUtil.getDeclaredConstructor(className, BCX509ExtendedTrustManager.class);
                }
            }
            catch (Exception e)
            {
            }
            exportX509TrustManagerConstructor = constructor;
        }

        {
            Constructor<? extends BCX509ExtendedTrustManager> constructor = null;
            if (null != x509ExtendedTrustManagerClass)
            {
                try
                {
                    String className = "org.bouncycastle.jsse.provider.ImportX509TrustManager_7";

                    constructor = ReflectionUtil.getDeclaredConstructor(className, x509ExtendedTrustManagerClass);
                }
                catch (Exception e)
                {
                }
            }
            importX509TrustManagerConstructor = constructor;
        }
    }

    static X509TrustManager exportX509TrustManager(BCX509ExtendedTrustManager x509TrustManager)
    {
        if (x509TrustManager instanceof ImportX509TrustManager)
        {
            return ((ImportX509TrustManager)x509TrustManager).unwrap();
        }

        if (null != exportX509TrustManagerConstructor)
        {
            try
            {
                return exportX509TrustManagerConstructor.newInstance(x509TrustManager);
            }
            catch (Exception e)
            {
            }
        }

        return new ExportX509TrustManager_5(x509TrustManager);
    }

    static BCX509ExtendedTrustManager importX509TrustManager(boolean isInFipsMode, JcaJceHelper helper,
        X509TrustManager x509TrustManager)
    {
        if (x509TrustManager instanceof BCX509ExtendedTrustManager)
        {
            return (BCX509ExtendedTrustManager)x509TrustManager;
        }

        if (x509TrustManager instanceof ExportX509TrustManager)
        {
            return ((ExportX509TrustManager)x509TrustManager).unwrap();
        }

        if (null != importX509TrustManagerConstructor && x509ExtendedTrustManagerClass.isInstance(x509TrustManager))
        {
            try
            {
                return importX509TrustManagerConstructor.newInstance(x509TrustManager);
            }
            catch (Exception e)
            {
            }
        }

        return new ImportX509TrustManager_5(isInFipsMode, helper, x509TrustManager);
    }
}
