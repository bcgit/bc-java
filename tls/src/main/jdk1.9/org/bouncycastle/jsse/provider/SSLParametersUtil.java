package org.bouncycastle.jsse.provider;

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

        ssl.setAlgorithmConstraints(JsseUtils_7.exportAlgorithmConstraints(prov.getAlgorithmConstraints()));

        ssl.setEndpointIdentificationAlgorithm(prov.getEndpointIdentificationAlgorithm());

        // From JDK 1.8

        ssl.setUseCipherSuitesOrder(prov.getUseCipherSuitesOrder());

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

        // From JDK 9

        ssl.setApplicationProtocols(prov.getApplicationProtocols());

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

        {
            AlgorithmConstraints constraints = ssl.getAlgorithmConstraints();
            if (null != constraints)
            {
                bc.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraints(constraints));
            }
        }

        {
            String endpointIdentificationAlgorithm = ssl.getEndpointIdentificationAlgorithm();
            if (null != endpointIdentificationAlgorithm)
            {
                bc.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        // From JDK 1.8

        bc.setUseCipherSuitesOrder(ssl.getUseCipherSuitesOrder());

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

        // From JDK 9

        {
            String[] getApplicationProtocolsResult = ssl.getApplicationProtocols();
            if (null != getApplicationProtocolsResult)
            {
                bc.setApplicationProtocols(getApplicationProtocolsResult);
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

        {
            AlgorithmConstraints constraints = ssl.getAlgorithmConstraints();
            if (null != constraints)
            {
                prov.setAlgorithmConstraints(JsseUtils_7.importAlgorithmConstraints(constraints));
            }
        }

        {
            String endpointIdentificationAlgorithm = ssl.getEndpointIdentificationAlgorithm();
            if (null != endpointIdentificationAlgorithm)
            {
                prov.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
            }
        }

        // From JDK 1.8

        prov.setUseCipherSuitesOrder(ssl.getUseCipherSuitesOrder());

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

        // From JDK 9

        {
            String[] getApplicationProtocolsResult = ssl.getApplicationProtocols();
            if (null != getApplicationProtocolsResult)
            {
                prov.setApplicationProtocols(getApplicationProtocolsResult);
            }
        }
    }
}
