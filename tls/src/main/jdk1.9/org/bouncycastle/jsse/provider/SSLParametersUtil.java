package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
import java.security.AlgorithmConstraints;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;

import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

abstract class SSLParametersUtil
{
    private static final Method getNamedGroups;
    private static final Method setNamedGroups;
    private static final Method getSignatureSchemes;
    private static final Method setSignatureSchemes;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLParameters");

        getNamedGroups = ReflectionUtil.findMethod(methods, "getNamedGroups");
        setNamedGroups = ReflectionUtil.findMethod(methods, "setNamedGroups");
        getSignatureSchemes = ReflectionUtil.findMethod(methods, "getSignatureSchemes");
        setSignatureSchemes = ReflectionUtil.findMethod(methods, "setSignatureSchemes");
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

        ssl.setEndpointIdentificationAlgorithm(prov.getEndpointIdentificationAlgorithm());

        ssl.setAlgorithmConstraints(JsseUtils_7.exportAlgorithmConstraints(prov.getAlgorithmConstraints()));

        // From JDK 8

        {
            List<BCSNIServerName> serverNames = prov.getServerNames();
            if (null != serverNames)
            {
                ssl.setServerNames(JsseUtils_8.exportSNIServerNames(serverNames));
            }
        }

        {
            Collection<BCSNIMatcher> matchers = prov.getSNIMatchers();
            if (null != matchers)
            {
                ssl.setSNIMatchers(JsseUtils_8.exportSNIMatchers(matchers));
            }
        }

        ssl.setUseCipherSuitesOrder(prov.getUseCipherSuitesOrder());

        // From JDK 9 originally, then added to 8u251

        {
            String[] applicationProtocols = prov.getApplicationProtocols();
            if (null != applicationProtocols)
            {
                ssl.setApplicationProtocols(applicationProtocols);
            }
        }

        // From JDK 9

        ssl.setEnableRetransmissions(prov.getEnableRetransmissions());

        ssl.setMaximumPacketSize(prov.getMaximumPacketSize());

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

        {
            String endpointIdentificationAlgorithm = ssl.getEndpointIdentificationAlgorithm();
            if (null != endpointIdentificationAlgorithm)
            {
                bc.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        {
            AlgorithmConstraints constraints = ssl.getAlgorithmConstraints();
            if (null != constraints)
            {
                bc.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraints(constraints));
            }
        }

        // From JDK 8

        {
            List<SNIServerName> serverNames = ssl.getServerNames();
            if (null != serverNames)
            {
                bc.setServerNames(JsseUtils_8.importSNIServerNames(serverNames));
            }
        }

        {
            Collection<SNIMatcher> matchers = ssl.getSNIMatchers();
            if (null != matchers)
            {
                bc.setSNIMatchers(JsseUtils_8.importSNIMatchers(matchers));
            }
        }

        bc.setUseCipherSuitesOrder(ssl.getUseCipherSuitesOrder());

        // From JDK 9 originally, then added to 8u251

        {
            String[] applicationProtocols = ssl.getApplicationProtocols();
            if (null != applicationProtocols)
            {
                bc.setApplicationProtocols(applicationProtocols);
            }
        }

        // From JDK 9

        bc.setEnableRetransmissions(ssl.getEnableRetransmissions());

        bc.setMaximumPacketSize(ssl.getMaximumPacketSize());

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

        {
            String endpointIdentificationAlgorithm = ssl.getEndpointIdentificationAlgorithm();
            if (null != endpointIdentificationAlgorithm)
            {
                prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        {
            AlgorithmConstraints constraints = ssl.getAlgorithmConstraints();
            if (null != constraints)
            {
                prov.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraints(constraints));
            }
        }

        // From JDK 8

        {
            List<SNIServerName> serverNames = ssl.getServerNames();
            if (null != serverNames)
            {
                prov.setServerNames(JsseUtils_8.importSNIServerNames(serverNames));
            }
        }

        {
            Collection<SNIMatcher> matchers = ssl.getSNIMatchers();
            if (null != matchers)
            {
                prov.setSNIMatchers(JsseUtils_8.importSNIMatchers(matchers));
            }
        }

        prov.setUseCipherSuitesOrder(ssl.getUseCipherSuitesOrder());

        // From JDK 9 originally, then added to 8u251

        {
            String[] applicationProtocols = ssl.getApplicationProtocols();
            if (null != applicationProtocols)
            {
                prov.setApplicationProtocols(applicationProtocols);
            }
        }

        // From JDK 9

        prov.setEnableRetransmissions(ssl.getEnableRetransmissions());

        prov.setMaximumPacketSize(ssl.getMaximumPacketSize());

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
