package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCApplicationProtocolSelector;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;

final class ProvSSLParameters
{
    private static <T> List<T> copyList(Collection<T> list)
    {
        if (list == null)
        {
            return null;
        }
        if (list.isEmpty())
        {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(new ArrayList<T>(list));
    }

    private final ProvSSLContextSpi context;

    private String[] cipherSuites;
    private String[] protocols;
    private boolean needClientAuth = false;
    private boolean wantClientAuth = false;
    private BCAlgorithmConstraints algorithmConstraints = ProvAlgorithmConstraints.DEFAULT;
    private String endpointIdentificationAlgorithm;
    private boolean useCipherSuitesOrder = true;
    private List<BCSNIMatcher> sniMatchers;
    private List<BCSNIServerName> sniServerNames;
    private String[] applicationProtocols = new String[0];
    private BCApplicationProtocolSelector<SSLEngine> engineAPSelector;
    private BCApplicationProtocolSelector<SSLSocket> socketAPSelector;
    private ProvSSLSession sessionToResume;

    ProvSSLParameters(ProvSSLContextSpi context, String[] cipherSuites, String[] protocols)
    {
        this.context = context;

        this.cipherSuites = cipherSuites;
        this.protocols = protocols;
    }

    ProvSSLParameters copy()
    {
        ProvSSLParameters p = new ProvSSLParameters(context, cipherSuites, protocols);
        p.needClientAuth = needClientAuth;
        p.wantClientAuth = wantClientAuth;
        p.algorithmConstraints = algorithmConstraints;
        p.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
        p.useCipherSuitesOrder = useCipherSuitesOrder;
        p.sniMatchers = sniMatchers;
        p.sniServerNames = sniServerNames;
        p.applicationProtocols = applicationProtocols;
        p.engineAPSelector = engineAPSelector;
        p.socketAPSelector = socketAPSelector;
        p.sessionToResume = sessionToResume;
        return p;
    }

    ProvSSLParameters copyForConnection()
    {
        ProvSSLParameters p = copy();

        if (ProvAlgorithmConstraints.DEFAULT != p.algorithmConstraints)
        {
            p.algorithmConstraints = new ProvAlgorithmConstraints(p.algorithmConstraints, true);
        }

        return p;
    }

    public String[] getCipherSuites()
    {
        return cipherSuites.clone();
    }

    String[] getCipherSuitesArray()
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        return cipherSuites;
    }

    public void setCipherSuites(String[] cipherSuites)
    {
        this.cipherSuites = context.getSupportedCipherSuites(cipherSuites);
    }

    void setCipherSuitesArray(String[] cipherSuites)
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        this.cipherSuites = cipherSuites;
    }

    public String[] getProtocols()
    {
        return protocols.clone();
    }

    String[] getProtocolsArray()
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        return protocols;
    }

    public void setProtocols(String[] protocols)
    {
        if (!context.isSupportedProtocols(protocols))
        {
            throw new IllegalArgumentException("'protocols' cannot be null, or contain unsupported protocols");
        }

        this.protocols = protocols.clone();
    }

    void setProtocolsArray(String[] protocols)
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        this.protocols = protocols;
    }

    public boolean getNeedClientAuth()
    {
        return needClientAuth;
    }

    public void setNeedClientAuth(boolean needClientAuth)
    {
        this.needClientAuth = needClientAuth;
        this.wantClientAuth = false;
    }

    public boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth)
    {
        this.needClientAuth = false;
        this.wantClientAuth = wantClientAuth;
    }

    public BCAlgorithmConstraints getAlgorithmConstraints()
    {
        return algorithmConstraints;
    }

    public void setAlgorithmConstraints(BCAlgorithmConstraints algorithmConstraints)
    {
        this.algorithmConstraints = algorithmConstraints;
    }

    public String getEndpointIdentificationAlgorithm()
    {
        return endpointIdentificationAlgorithm;
    }

    public void setEndpointIdentificationAlgorithm(String endpointIdentificationAlgorithm)
    {
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
    }

    public boolean getUseCipherSuitesOrder()
    {
        return useCipherSuitesOrder;
    }

    public void setUseCipherSuitesOrder(boolean useCipherSuitesOrder)
    {
        this.useCipherSuitesOrder = useCipherSuitesOrder;
    }

    public List<BCSNIServerName> getServerNames()
    {
        return copyList(sniServerNames);
    }

    public void setServerNames(List<BCSNIServerName> serverNames)
    {
        this.sniServerNames = copyList(serverNames);
    }

    public Collection<BCSNIMatcher> getSNIMatchers()
    {
        return copyList(sniMatchers);
    }

    public void setSNIMatchers(Collection<BCSNIMatcher> matchers)
    {
        this.sniMatchers = copyList(matchers);
    }

    public String[] getApplicationProtocols()
    {
        return applicationProtocols.clone();
    }

    public void setApplicationProtocols(String[] applicationProtocols)
    {
        this.applicationProtocols = applicationProtocols.clone();
    }
    
    public BCApplicationProtocolSelector<SSLEngine> getEngineAPSelector()
    {
        return engineAPSelector;
    }
    
    public void setEngineAPSelector(BCApplicationProtocolSelector<SSLEngine> engineAPSelector)
    {
        this.engineAPSelector = engineAPSelector;
    }

    public BCApplicationProtocolSelector<SSLSocket> getSocketAPSelector()
    {
        return socketAPSelector;
    }

    public void setSocketAPSelector(BCApplicationProtocolSelector<SSLSocket> socketAPSelector)
    {
        this.socketAPSelector = socketAPSelector;
    }

    public ProvSSLSession getSessionToResume()
    {
        return sessionToResume;
    }

    public void setSessionToResume(ProvSSLSession sessionToResume)
    {
        this.sessionToResume = sessionToResume;
    }
}
