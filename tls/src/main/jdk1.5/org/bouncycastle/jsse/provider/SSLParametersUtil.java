package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
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
    private static final Method getEndpointIdentificationAlgorithm;
    private static final Method setEndpointIdentificationAlgorithm;
    private static final Method getServerNames;
    private static final Method setServerNames;
    private static final Method getSNIMatchers;
    private static final Method setSNIMatchers;
    private static final Method getUseCipherSuitesOrder;
    private static final Method setUseCipherSuitesOrder;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLParameters");

        getAlgorithmConstraints = ReflectionUtil.findMethod(methods, "getAlgorithmConstraints");
        setAlgorithmConstraints = ReflectionUtil.findMethod(methods, "setAlgorithmConstraints");
        getEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "getEndpointIdentificationAlgorithm");
        setEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "setEndpointIdentificationAlgorithm");
        getServerNames = ReflectionUtil.findMethod(methods, "getServerNames");
        setServerNames = ReflectionUtil.findMethod(methods, "setServerNames");
        getSNIMatchers = ReflectionUtil.findMethod(methods, "getSNIMatchers");
        setSNIMatchers = ReflectionUtil.findMethod(methods, "setSNIMatchers");
        getUseCipherSuitesOrder = ReflectionUtil.findMethod(methods, "getUseCipherSuitesOrder");
        setUseCipherSuitesOrder = ReflectionUtil.findMethod(methods, "setUseCipherSuitesOrder");
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
            set(ssl, setAlgorithmConstraints, JsseUtils_7.exportAlgorithmConstraints(prov.getAlgorithmConstraints()));
        }

        if (null != setEndpointIdentificationAlgorithm)
        {
            set(ssl, setEndpointIdentificationAlgorithm, prov.getEndpointIdentificationAlgorithm());
        }

        // From JDK 1.8

        if (null != setUseCipherSuitesOrder)
        {
            set(ssl, setUseCipherSuitesOrder, prov.getUseCipherSuitesOrder());
        }

        if (null != setServerNames)
        {
            List<BCSNIServerName> serverNames = prov.getServerNames();
            if (null != serverNames)
            {
                set(ssl, setServerNames, JsseUtils_8.exportSNIServerNames(serverNames));
            }
        }

        if (null != setSNIMatchers)
        {
            Collection<BCSNIMatcher> sniMatchers = prov.getSNIMatchers();
            if (null != sniMatchers)
            {
                set(ssl, setSNIMatchers, JsseUtils_8.exportSNIMatchers(sniMatchers));
            }
        }

        return ssl;
    }

    static BCSSLParameters importSSLParameters(SSLParameters ssl)
    {
        BCSSLParameters bc = new BCSSLParameters(ssl.getCipherSuites(), ssl.getProtocols());

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (ssl.getNeedClientAuth())
        {
            bc.setNeedClientAuth(true);
        }
        else if (ssl.getWantClientAuth())
        {
            bc.setWantClientAuth(true);
        }
        else
        {
            bc.setWantClientAuth(false);
        }

        // From JDK 1.7

        if (null != getAlgorithmConstraints)
        {
            Object getAlgorithmConstraintsResult = get(ssl, getAlgorithmConstraints);
            if (null != getAlgorithmConstraintsResult)
            {
                bc.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraints(getAlgorithmConstraintsResult));
            }
        }

        if (null != getEndpointIdentificationAlgorithm)
        {
            String endpointIdentificationAlgorithm = (String)get(ssl, getEndpointIdentificationAlgorithm);
            if (null != endpointIdentificationAlgorithm)
            {
                bc.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        // From JDK 1.8

        if (null != getUseCipherSuitesOrder)
        {
            bc.setUseCipherSuitesOrder((Boolean)get(ssl, getUseCipherSuitesOrder));
        }

        if (null != getServerNames)
        {
            Object getServerNamesResult = get(ssl, getServerNames);
            if (null != getServerNamesResult)
            {
                bc.setServerNames(JsseUtils_8.importSNIServerNames(getServerNamesResult));
            }
        }

        if (null != getSNIMatchers)
        {
            Object getSNIMatchersResult = get(ssl, getSNIMatchers);
            if (null != getSNIMatchersResult)
            {
                bc.setSNIMatchers(JsseUtils_8.importSNIMatchers(getSNIMatchersResult));
            }
        }

        return bc;
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
            Object getAlgorithmConstraintsResult = get(ssl, getAlgorithmConstraints);
            if (null != getAlgorithmConstraintsResult)
            {
                prov.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraints(getAlgorithmConstraintsResult));
            }
        }

        if (null != getEndpointIdentificationAlgorithm)
        {
            String endpointIdentificationAlgorithm = (String)get(ssl, getEndpointIdentificationAlgorithm);
            if (null != endpointIdentificationAlgorithm)
            {
                prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        // From JDK 1.8

        if (null != getUseCipherSuitesOrder)
        {
            prov.setUseCipherSuitesOrder((Boolean)get(ssl, getUseCipherSuitesOrder));
        }

        if (null != getServerNames)
        {
            Object getServerNamesResult = get(ssl, getServerNames);
            if (null != getServerNamesResult)
            {
                prov.setServerNames(JsseUtils_8.importSNIServerNames(getServerNamesResult));
            }
        }

        if (null != getSNIMatchers)
        {
            Object getSNIMatchersResult = get(ssl, getSNIMatchers);
            if (null != getSNIMatchersResult)
            {
                prov.setSNIMatchers(JsseUtils_8.importSNIMatchers(getSNIMatchersResult));
            }
        }
    }

    private static Object get(Object obj, Method method)
    {
        return ReflectionUtil.invokeGetter(obj, method);
    }

    private static void set(Object obj, Method method, Object arg)
    {
        ReflectionUtil.invokeSetter(obj, method, arg);
    }
}
