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
    private static final Method getApplicationProtocols;
    private static final Method setApplicationProtocols;
    private static final Method getEnableRetransmissions;
    private static final Method setEnableRetransmissions;
    private static final Method getEndpointIdentificationAlgorithm;
    private static final Method setEndpointIdentificationAlgorithm;
    private static final Method getMaximumPacketSize;
    private static final Method setMaximumPacketSize;
    private static final Method getNamedGroups;
    private static final Method setNamedGroups;
    private static final Method getServerNames;
    private static final Method setServerNames;
    private static final Method getSignatureSchemes;
    private static final Method setSignatureSchemes;
    private static final Method getSNIMatchers;
    private static final Method setSNIMatchers;
    private static final Method getUseCipherSuitesOrder;
    private static final Method setUseCipherSuitesOrder;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLParameters");

        getAlgorithmConstraints = ReflectionUtil.findMethod(methods, "getAlgorithmConstraints");
        setAlgorithmConstraints = ReflectionUtil.findMethod(methods, "setAlgorithmConstraints");
        getApplicationProtocols = ReflectionUtil.findMethod(methods, "getApplicationProtocols");
        setApplicationProtocols = ReflectionUtil.findMethod(methods, "setApplicationProtocols");
        getEnableRetransmissions = ReflectionUtil.findMethod(methods, "getEnableRetransmissions");
        setEnableRetransmissions = ReflectionUtil.findMethod(methods, "setEnableRetransmissions");
        getEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "getEndpointIdentificationAlgorithm");
        setEndpointIdentificationAlgorithm = ReflectionUtil.findMethod(methods, "setEndpointIdentificationAlgorithm");
        getMaximumPacketSize = ReflectionUtil.findMethod(methods, "getMaximumPacketSize");
        setMaximumPacketSize = ReflectionUtil.findMethod(methods, "setMaximumPacketSize");
        getNamedGroups = ReflectionUtil.findMethod(methods, "getNamedGroups");
        setNamedGroups = ReflectionUtil.findMethod(methods, "setNamedGroups");
        getServerNames = ReflectionUtil.findMethod(methods, "getServerNames");
        setServerNames = ReflectionUtil.findMethod(methods, "setServerNames");
        getSignatureSchemes = ReflectionUtil.findMethod(methods, "getSignatureSchemes");
        setSignatureSchemes = ReflectionUtil.findMethod(methods, "setSignatureSchemes");
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
        else
        {
            ssl.setWantClientAuth(prov.getWantClientAuth());
        }

        ssl.setEndpointIdentificationAlgorithm(prov.getEndpointIdentificationAlgorithm());
        ssl.setAlgorithmConstraints(prov.getAlgorithmConstraints());
        ssl.setServerNames(prov.getServerNames());
        ssl.setSNIMatchers(prov.getSNIMatchers());
        ssl.setUseCipherSuitesOrder(prov.getUseCipherSuitesOrder());
        ssl.setApplicationProtocols(prov.getApplicationProtocols());
        ssl.setEnableRetransmissions(prov.getEnableRetransmissions());
        ssl.setMaximumPacketSize(prov.getMaximumPacketSize());
        ssl.setSignatureSchemes(prov.getSignatureSchemes());
        ssl.setNamedGroups(prov.getNamedGroups());

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
        else
        {
            ssl.setWantClientAuth(prov.getWantClientAuth());
        }

        // From JDK 1.7

        if (null != setAlgorithmConstraints)
        {
            set(ssl, setAlgorithmConstraints,
                JsseUtils_7.exportAlgorithmConstraintsDynamic(prov.getAlgorithmConstraints()));
        }

        if (null != setEndpointIdentificationAlgorithm)
        {
            set(ssl, setEndpointIdentificationAlgorithm, prov.getEndpointIdentificationAlgorithm());
        }

        // From JDK 8

        if (null != setServerNames)
        {
            List<BCSNIServerName> serverNames = prov.getServerNames();
            if (null != serverNames)
            {
                set(ssl, setServerNames, JsseUtils_8.exportSNIServerNamesDynamic(serverNames));
            }
        }

        if (null != setSNIMatchers)
        {
            Collection<BCSNIMatcher> matchers = prov.getSNIMatchers();
            if (null != matchers)
            {
                set(ssl, setSNIMatchers, JsseUtils_8.exportSNIMatchersDynamic(matchers));
            }
        }

        if (null != setUseCipherSuitesOrder)
        {
            set(ssl, setUseCipherSuitesOrder, prov.getUseCipherSuitesOrder());
        }

        // From JDK 9 originally, then added to 8u251

        if (null != setApplicationProtocols)
        {
            String[] applicationProtocols = prov.getApplicationProtocols();
            if (null != applicationProtocols)
            {
                set(ssl, setApplicationProtocols, applicationProtocols);
            }
        }

        // From JDK 9

        if (null != setEnableRetransmissions)
        {
            set(ssl, setEnableRetransmissions, prov.getEnableRetransmissions());
        }

        if (null != setMaximumPacketSize)
        {
            set(ssl, setMaximumPacketSize, prov.getMaximumPacketSize());
        }

        // From JDK 19

        if (null != setSignatureSchemes)
        {
            set(ssl, setSignatureSchemes, prov.getSignatureSchemes());
        }

        // From JDK 20

        if (null != setNamedGroups)
        {
            set(ssl, setNamedGroups, prov.getNamedGroups());
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
        else
        {
            bc.setWantClientAuth(ssl.getWantClientAuth());
        }

        // From JDK 1.7

        if (null != getEndpointIdentificationAlgorithm)
        {
            String endpointIdentificationAlgorithm = (String)get(ssl, getEndpointIdentificationAlgorithm);
            if (null != endpointIdentificationAlgorithm)
            {
                bc.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        if (null != getAlgorithmConstraints)
        {
            Object constraints = get(ssl, getAlgorithmConstraints);
            if (null != constraints)
            {
                bc.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraintsDynamic(constraints));
            }
        }

        // From JDK 8

        if (null != getServerNames)
        {
            Object serverNames = get(ssl, getServerNames);
            if (null != serverNames)
            {
                bc.setServerNames(JsseUtils_8.importSNIServerNamesDynamic(serverNames));
            }
        }

        if (null != getSNIMatchers)
        {
            Object matchers = get(ssl, getSNIMatchers);
            if (null != matchers)
            {
                bc.setSNIMatchers(JsseUtils_8.importSNIMatchersDynamic(matchers));
            }
        }

        if (null != getUseCipherSuitesOrder)
        {
            bc.setUseCipherSuitesOrder((Boolean)get(ssl, getUseCipherSuitesOrder));
        }

        // From JDK 9 originally, then added to 8u251

        if (null != getApplicationProtocols)
        {
            String[] applicationProtocols = (String[])get(ssl, getApplicationProtocols);
            if (null != applicationProtocols)
            {
                bc.setApplicationProtocols(applicationProtocols);
            }
        }

        // From JDK 9

        if (null != getEnableRetransmissions)
        {
            bc.setEnableRetransmissions((Boolean)get(ssl, getEnableRetransmissions));
        }

        if (null != getMaximumPacketSize)
        {
            bc.setMaximumPacketSize((Integer)get(ssl, getMaximumPacketSize));
        }

        // From JDK 19

        if (null != getSignatureSchemes)
        {
            bc.setSignatureSchemes((String[])get(ssl, getSignatureSchemes));
        }

        // From JDK 20

        if (null != getNamedGroups)
        {
            bc.setNamedGroups((String[])get(ssl, getNamedGroups));
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
        else
        {
            prov.setWantClientAuth(ssl.getWantClientAuth());
        }

        String endpointIdentificationAlgorithm = ssl.getEndpointIdentificationAlgorithm();
        if (null != endpointIdentificationAlgorithm)
        {
            prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        }

        BCAlgorithmConstraints algorithmConstraints = ssl.getAlgorithmConstraints();
        if (null != algorithmConstraints)
        {
            prov.setAlgorithmConstraints(algorithmConstraints);
        }

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

        prov.setUseCipherSuitesOrder(ssl.getUseCipherSuitesOrder());

        String[] applicationProtocols = ssl.getApplicationProtocols();
        if (null != applicationProtocols)
        {
            prov.setApplicationProtocols(applicationProtocols);
        }

        prov.setEnableRetransmissions(ssl.getEnableRetransmissions());

        prov.setMaximumPacketSize(ssl.getMaximumPacketSize());

        prov.setSignatureSchemes(ssl.getSignatureSchemes());

        prov.setNamedGroups(ssl.getNamedGroups());
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
        else
        {
            prov.setWantClientAuth(ssl.getWantClientAuth());
        }

        // From JDK 1.7

        if (null != getEndpointIdentificationAlgorithm)
        {
            String endpointIdentificationAlgorithm = (String)get(ssl, getEndpointIdentificationAlgorithm);
            if (null != endpointIdentificationAlgorithm)
            {
                prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        if (null != getAlgorithmConstraints)
        {
            Object constraints = get(ssl, getAlgorithmConstraints);
            if (null != constraints)
            {
                prov.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraintsDynamic(constraints));
            }
        }

        // From JDK 8

        if (null != getServerNames)
        {
            Object serverNames = get(ssl, getServerNames);
            if (null != serverNames)
            {
                prov.setServerNames(JsseUtils_8.importSNIServerNamesDynamic(serverNames));
            }
        }

        if (null != getSNIMatchers)
        {
            Object matchers = get(ssl, getSNIMatchers);
            if (null != matchers)
            {
                prov.setSNIMatchers(JsseUtils_8.importSNIMatchersDynamic(matchers));
            }
        }

        if (null != getUseCipherSuitesOrder)
        {
            prov.setUseCipherSuitesOrder((Boolean)get(ssl, getUseCipherSuitesOrder));
        }

        // From JDK 9 originally, then added to 8u251

        if (null != getApplicationProtocols)
        {
            String[] applicationProtocols = (String[])get(ssl, getApplicationProtocols);
            if (null != applicationProtocols)
            {
                prov.setApplicationProtocols(applicationProtocols);
            }
        }

        // From JDK 9

        if (null != getEnableRetransmissions)
        {
            prov.setEnableRetransmissions((Boolean)get(ssl, getEnableRetransmissions));
        }

        if (null != getMaximumPacketSize)
        {
            prov.setMaximumPacketSize((Integer)get(ssl, getMaximumPacketSize));
        }

        // From JDK 19

        if (null != getSignatureSchemes)
        {
            prov.setSignatureSchemes((String[])get(ssl, getSignatureSchemes));
        }

        // From JDK 20

        if (null != getNamedGroups)
        {
            prov.setNamedGroups((String[])get(ssl, getNamedGroups));
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
