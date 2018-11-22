package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLParameters;

import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

abstract class SSLParametersUtil
{
    private static final Method getAlgorithmConstraints;
    private static final Method setAlgorithmConstraints;
    private static final Method getApplicationProtocols;
    private static final Method setApplicationProtocols;
    private static final Method getEndpointIdentificationAlgorithm;
    private static final Method setEndpointIdentificationAlgorithm;
    private static final Method getServerNames;
    private static final Method setServerNames;
    private static final Method getSNIMatchers;
    private static final Method setSNIMatchers;
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
        getApplicationProtocols = findMethod(methods, "getApplicationProtocols");
        setApplicationProtocols = findMethod(methods, "setApplicationProtocols");
        getEndpointIdentificationAlgorithm = findMethod(methods, "getEndpointIdentificationAlgorithm");
        setEndpointIdentificationAlgorithm = findMethod(methods, "setEndpointIdentificationAlgorithm");
        getServerNames = findMethod(methods, "getServerNames");
        setServerNames = findMethod(methods, "setServerNames");
        getSNIMatchers = findMethod(methods, "getSNIMatchers");
        setSNIMatchers = findMethod(methods, "setSNIMatchers");
        getUseCipherSuitesOrder = findMethod(methods, "getUseCipherSuitesOrder");
        setUseCipherSuitesOrder = findMethod(methods, "setUseCipherSuitesOrder");
    }

    static BCSSLParameters getParameters(ProvSSLParameters prov)
    {
        BCSSLParameters ssl = new BCSSLParameters(prov.getCipherSuites(), prov.getProtocols());

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (prov.getNeedClientAuth())
        {
            ssl.setNeedClientAuth(true);
        }
        else if (prov.getWantClientAuth())
        {
            ssl.setWantClientAuth(true);
        }
        else
        {
            ssl.setWantClientAuth(false);
        }

        ssl.setAlgorithmConstraints(prov.getAlgorithmConstraints());
        ssl.setEndpointIdentificationAlgorithm(prov.getEndpointIdentificationAlgorithm());
        ssl.setUseCipherSuitesOrder(prov.getUseCipherSuitesOrder());
        ssl.setServerNames(prov.getServerNames());
        ssl.setSNIMatchers(prov.getSNIMatchers());
        ssl.setApplicationProtocols(prov.getApplicationProtocols());

        return ssl;
    }

    static SSLParameters getSSLParameters(ProvSSLParameters prov)
    {
        SSLParameters ssl = new SSLParameters(prov.getCipherSuites(), prov.getProtocols());

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (prov.getNeedClientAuth())
        {
            ssl.setNeedClientAuth(true);
        }
        else if (prov.getWantClientAuth())
        {
            ssl.setWantClientAuth(true);
        }
        else
        {
            ssl.setWantClientAuth(false);
        }

        // From JDK 1.7

        if (null != setAlgorithmConstraints)
        {
            invokeSetterPrivileged(ssl, setAlgorithmConstraints,
                JsseUtils_7.exportAlgorithmConstraints(prov.getAlgorithmConstraints()));
        }

        if (null != setEndpointIdentificationAlgorithm)
        {
            invokeSetterPrivileged(ssl, setEndpointIdentificationAlgorithm, prov.getEndpointIdentificationAlgorithm());
        }

        // From JDK 1.8

        if (null != setUseCipherSuitesOrder)
        {
            invokeSetterPrivileged(ssl, setUseCipherSuitesOrder, prov.getUseCipherSuitesOrder());
        }

        if (null != setServerNames)
        {
            invokeSetterPrivileged(ssl, setServerNames, JsseUtils_8.exportSNIServerNames(prov.getServerNames()));
        }

        if (null != setSNIMatchers)
        {
            invokeSetterPrivileged(ssl, setSNIMatchers, JsseUtils_8.exportSNIMatchers(prov.getSNIMatchers()));
        }

        // From JDK 9

        if (null != setApplicationProtocols)
        {
            invokeSetterPrivileged(ssl, setApplicationProtocols, prov.getApplicationProtocols());
        }

        return ssl;
    }

    static void setParameters(ProvSSLParameters prov, BCSSLParameters ssl)
    {
        String[] cipherSuites = ssl.getCipherSuites();
        if (null != cipherSuites)
        {
            prov.setCipherSuites(cipherSuites);
        }

        String[] protocols = ssl.getProtocols();
        if (null != protocols)
        {
            prov.setProtocols(protocols);
        }

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (ssl.getNeedClientAuth())
        {
            prov.setNeedClientAuth(true);
        }
        else if (ssl.getWantClientAuth())
        {
            prov.setWantClientAuth(true);
        }
        else
        {
            prov.setWantClientAuth(false);
        }

        BCAlgorithmConstraints algorithmConstraints = ssl.getAlgorithmConstraints();
        if (null != algorithmConstraints)
        {
            prov.setAlgorithmConstraints(algorithmConstraints);
        }

        String endpointIdentificationAlgorithm = ssl.getEndpointIdentificationAlgorithm();
        if (null != endpointIdentificationAlgorithm)
        {
            prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }

        prov.setUseCipherSuitesOrder(ssl.getUseCipherSuitesOrder());

        List<BCSNIServerName> serverNames = ssl.getServerNames();
        if (null != serverNames)
        {
            prov.setServerNames(serverNames);
        }

        Collection<BCSNIMatcher> sniMatchers = ssl.getSNIMatchers();
        if (null != sniMatchers)
        {
            prov.setSNIMatchers(sniMatchers);
        }

        String[] applicationProtocols = ssl.getApplicationProtocols();
        if (null != applicationProtocols)
        {
            prov.setApplicationProtocols(applicationProtocols);
        }
    }

    static void setSSLParameters(ProvSSLParameters prov, SSLParameters ssl)
    {
        String[] cipherSuites = ssl.getCipherSuites();
        if (null != cipherSuites)
        {
            prov.setCipherSuites(cipherSuites);
        }

        String[] protocols = ssl.getProtocols();
        if (null != protocols)
        {
            prov.setProtocols(protocols);
        }

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (ssl.getNeedClientAuth())
        {
            prov.setNeedClientAuth(true);
        }
        else if (ssl.getWantClientAuth())
        {
            prov.setWantClientAuth(true);
        }
        else
        {
            prov.setWantClientAuth(false);
        }

        // From JDK 1.7

        if (null != getAlgorithmConstraints)
        {
            Object getAlgorithmConstraintsResult = invokeGetterPrivileged(ssl, getAlgorithmConstraints);
            if (null != getAlgorithmConstraintsResult)
            {
                prov.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraints(getAlgorithmConstraintsResult));
            }
        }

        if (null != getEndpointIdentificationAlgorithm)
        {
            String endpointIdentificationAlgorithm = (String)invokeGetterPrivileged(ssl, getEndpointIdentificationAlgorithm);
            if (null != endpointIdentificationAlgorithm)
            {
                prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        // From JDK 1.8

        if (null != getUseCipherSuitesOrder)
        {
            prov.setUseCipherSuitesOrder((Boolean)invokeGetterPrivileged(ssl, getUseCipherSuitesOrder));
        }

        if (null != getServerNames)
        {
            Object getServerNamesResult = invokeGetterPrivileged(ssl, getServerNames);
            if (null != getServerNamesResult)
            {
                prov.setServerNames(JsseUtils_8.importSNIServerNames(getServerNamesResult));
            }
        }

        if (null != getSNIMatchers)
        {
            Object getSNIMatchersResult = invokeGetterPrivileged(ssl, getSNIMatchers);
            if (null != getSNIMatchersResult)
            {
                prov.setSNIMatchers(JsseUtils_8.importSNIMatchers(getSNIMatchersResult));
            }
        }

        // From JDK 9

        if (null != getApplicationProtocols)
        {
            String[] getApplicationProtocolsResult = (String[])invokeGetterPrivileged(ssl, getApplicationProtocols);
            if (null != getApplicationProtocols)
            {
                prov.setApplicationProtocols(getApplicationProtocolsResult);
            }
        }
    }
}
