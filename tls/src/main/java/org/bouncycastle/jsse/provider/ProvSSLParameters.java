package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;

class ProvSSLParameters
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
    private Object algorithmConstraints;      // object not introduced till 1.6
    private String endpointIdentificationAlgorithm;
    private boolean useCipherSuitesOrder;
    private List<BCSNIMatcher> sniMatchers;
    private List<BCSNIServerName> sniServerNames;

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
        return p;
    }

    public void setCipherSuites(String[] cipherSuites)
    {
        if (!context.isSupportedCipherSuites(cipherSuites))
        {
            throw new IllegalArgumentException("'cipherSuites' cannot be null, or contain unsupported cipher suites");
        }

        this.cipherSuites = cipherSuites.clone();
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
        // NOTE: The mechanism of ProvSSLContextSpi.updateDefaultProtocols depends on this not making a copy
        this.protocols = protocols;
    }

    public void setNeedClientAuth(boolean needClientAuth)
    {
        this.needClientAuth = needClientAuth;
        this.wantClientAuth = false;
    }

    public void setWantClientAuth(boolean wantClientAuth)
    {
        this.needClientAuth = false;
        this.wantClientAuth = wantClientAuth;
    }

    public String[] getCipherSuites()
    {
        return cipherSuites.clone();
    }

    public String[] getProtocols()
    {
        return protocols.clone();
    }

    String[] getProtocolsArray()
    {
        // NOTE: The mechanism of ProvSSLContextSpi.updateDefaultProtocols depends on this not making a copy
        return protocols;
    }

    public boolean getNeedClientAuth()
    {
        return needClientAuth;
    }

    public boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    public Object getAlgorithmConstraints()
    {
        return algorithmConstraints;
    }

    public void setAlgorithmConstraints(Object algorithmConstraints)
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

    public void setUseCipherSuitesOrder(boolean honorOrder)
    {
        this.useCipherSuitesOrder = honorOrder;
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
}
