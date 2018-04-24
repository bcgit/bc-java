package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.net.ssl.SSLParameters;

abstract class SSLParametersUtil
{
    private static final Method getAlgorithmConstraints;
    private static final Method setAlgorithmConstraints;
    private static final Method getEndpointIdentificationAlgorithm;
    private static final Method setEndpointIdentificationAlgorithm;
    private static final Method getServerNames;
    private static final Method setServerNames;
    private static final Method getUseCipherSuitesOrder;
    private static final Method setUseCipherSuitesOrder;

    private static Method findMethod(Method[] methods, String name)
    {
        if (methods != null)
        {
            for (Method m : methods)
            {
                if (m.getName().equals(name))
                {
                    return m;
                }
            }
        }
        return null;
    }

    private static Class<?> getClassPrivileged(final String className)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Class<?>>()
        {
            public Class<?> run()
            {
                try
                {
                    ClassLoader loader = SSLParametersUtil.class.getClassLoader();
                    if (loader != null)
                    {
                        return loader.loadClass(className);
                    }

                    return Class.forName(className);
                }
                catch (Exception e)
                {
                    return null;
                }
            }
        });
    }

    private static Method[] getMethodsPrivileged(final Class<?> clazz)
    {
        if (clazz == null)
        {
            return null;
        }

        return AccessController.doPrivileged(new PrivilegedAction<Method[]>()
        {
            public Method[] run()
            {
                try
                {
                    return clazz.getMethods();
                }
                catch (Exception e)
                {
                    return null;
                }
            }
        });
    }

    private static Object invokeGetterPrivileged(final Object obj, final Method method)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    return method.invoke(obj);
                }
                catch (Exception e)
                {
                    // TODO: log?
                    return null;
                }
            }
        });
    }

    private static void invokeSetterPrivileged(final Object obj, final Method method, final Object arg)
    {
        AccessController.doPrivileged(new PrivilegedAction<Void>()
        {
            public Void run()
            {
                try
                {
                    method.invoke(obj, arg);
                }
                catch (Exception e)
                {
                    // TODO: log?
                }
                return null;
            }
        });
    }

    static
    {
        Class<?> sslParametersClazz = getClassPrivileged("javax.net.ssl.SSLParameters");
        
        Method[] methods = getMethodsPrivileged(sslParametersClazz);
        
        getAlgorithmConstraints = findMethod(methods, "getAlgorithmConstraints");
        setAlgorithmConstraints = findMethod(methods, "setAlgorithmConstraints");
        getEndpointIdentificationAlgorithm = findMethod(methods, "getEndpointIdentificationAlgorithm");
        setEndpointIdentificationAlgorithm = findMethod(methods, "setEndpointIdentificationAlgorithm");
        getServerNames = findMethod(methods, "getServerNames");
        setServerNames = findMethod(methods, "setServerNames");
        getUseCipherSuitesOrder = findMethod(methods, "getUseCipherSuitesOrder");
        setUseCipherSuitesOrder = findMethod(methods, "setUseCipherSuitesOrder");
    }

    static SSLParameters toSSLParameters(final ProvSSLParameters provSslParameters)
    {
        final SSLParameters r = new SSLParameters();
        r.setCipherSuites(provSslParameters.getCipherSuites());
        r.setProtocols(provSslParameters.getProtocols());
        // From JDK 1.7
        if (setAlgorithmConstraints != null)
        {
            invokeSetterPrivileged(r, setAlgorithmConstraints, provSslParameters.getAlgorithmConstraints());
        }
        if (setEndpointIdentificationAlgorithm != null)
        {
            invokeSetterPrivileged(r, setEndpointIdentificationAlgorithm, provSslParameters.getEndpointIdentificationAlgorithm());
        }
        // From JDK 1.8
        if (setServerNames != null)
        {
            invokeSetterPrivileged(r, setServerNames, JsseUtils_8.exportSNIServerNames(provSslParameters.getServerNames()));
        }
        // TODO[jsse] From JDK 1.8
//        r.setSNIMatchers(p.getSNIMatchers());
        if (setUseCipherSuitesOrder != null)
        {
            invokeSetterPrivileged(r, setUseCipherSuitesOrder, provSslParameters.getUseCipherSuitesOrder());
        }

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (provSslParameters.getNeedClientAuth())
        {
            r.setNeedClientAuth(true);
        }
        else if (provSslParameters.getWantClientAuth())
        {
            r.setWantClientAuth(true);
        }
        else
        {
            r.setWantClientAuth(false);
        }
        return r;
    }

    static ProvSSLParameters toProvSSLParameters(final SSLParameters sslParameters)
    {
        final ProvSSLParameters r = new ProvSSLParameters();
        r.setCipherSuites(sslParameters.getCipherSuites());
        r.setProtocols(sslParameters.getProtocols());
        // From JDK 1.7
        if (getAlgorithmConstraints != null)
        {
            r.setAlgorithmConstraints(invokeGetterPrivileged(sslParameters, getAlgorithmConstraints));
        }
        if (getEndpointIdentificationAlgorithm != null)
        {
            r.setEndpointIdentificationAlgorithm((String)invokeGetterPrivileged(sslParameters, getEndpointIdentificationAlgorithm));
        }
        // From JDK 1.8
        if (getServerNames != null)
        {
            r.setServerNames(JsseUtils_8.importSNIServerNames(invokeGetterPrivileged(sslParameters, getServerNames)));
        }
        // TODO[jsse] From JDK 1.8
//        r.setSNIMatchers(p.getSNIMatchers());
        if (getUseCipherSuitesOrder != null)
        {
            r.setUseCipherSuitesOrder((Boolean)invokeGetterPrivileged(sslParameters, getUseCipherSuitesOrder));
        }

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (sslParameters.getNeedClientAuth())
        {
            r.setNeedClientAuth(true);
        }
        else if (sslParameters.getWantClientAuth())
        {
            r.setWantClientAuth(true);
        }
        else
        {
            r.setWantClientAuth(false);
        }
        return r;
    }
}
