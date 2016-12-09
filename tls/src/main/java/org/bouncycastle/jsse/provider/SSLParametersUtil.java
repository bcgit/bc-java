package org.bouncycastle.jsse.provider;

import javax.net.ssl.SSLParameters;

public class SSLParametersUtil
{
    static SSLParameters toSSLParameters(ProvSSLParameters provSslParameters)
    {
        SSLParameters r = new SSLParameters();
        r.setCipherSuites(provSslParameters.getCipherSuites());
        r.setProtocols(provSslParameters.getProtocols());
        // TODO[jsse] From JDK 1.7
//        r.setAlgorithmConstraints(r.getAlgorithmConstraints());
//        r.setEndpointIdentificationAlgorithm(p.getEndpointIdentificationAlgorithm());
        // TODO[jsse] From JDK 1.8
//        r.setServerNames(p.getServerNames());
//        r.setSNIMatchers(p.getSNIMatchers());
//        r.setUseCipherSuitesOrder(p.getUseCipherSuitesOrder());

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

    static ProvSSLParameters toProvSSLParameters(SSLParameters sslParameters)
    {
        ProvSSLParameters r = new ProvSSLParameters();
        r.setCipherSuites(sslParameters.getCipherSuites());
        r.setProtocols(sslParameters.getProtocols());
        // TODO[jsse] From JDK 1.7
//        r.setAlgorithmConstraints(r.getAlgorithmConstraints());
//        r.setEndpointIdentificationAlgorithm(p.getEndpointIdentificationAlgorithm());
        // TODO[jsse] From JDK 1.8
//        r.setServerNames(p.getServerNames());
//        r.setSNIMatchers(p.getSNIMatchers());
//        r.setUseCipherSuitesOrder(p.getUseCipherSuitesOrder());

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
