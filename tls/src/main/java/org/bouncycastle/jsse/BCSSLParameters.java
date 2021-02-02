package org.bouncycastle.jsse;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.TlsUtils;

/**
 * A BCJSSE-specific interface providing access to extended SSL parameters in earlier JDKs.
 */
public final class BCSSLParameters
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

    private String[] applicationProtocols = TlsUtils.EMPTY_STRINGS;
    private String[] cipherSuites;
    private String[] protocols;
    private boolean wantClientAuth;
    private boolean needClientAuth;
    private String endpointIdentificationAlgorithm;
    private BCAlgorithmConstraints algorithmConstraints;
    private List<BCSNIServerName> serverNames;
    private List<BCSNIMatcher> sniMatchers;
    private boolean useCipherSuitesOrder;

    public BCSSLParameters()
    {
    }

    public BCSSLParameters(String[] cipherSuites)
    {
        setCipherSuites(cipherSuites);
    }

    public BCSSLParameters(String[] cipherSuites, String[] protocols)
    {
        setCipherSuites(cipherSuites);
        setProtocols(protocols);
    }

    public String[] getApplicationProtocols()
    {
        return TlsUtils.clone(applicationProtocols);
    }

    public void setApplicationProtocols(String[] applicationProtocols)
    {
        if (null == applicationProtocols)
        {
            throw new NullPointerException("'applicationProtocols' cannot be null");
        }

        String[] check = TlsUtils.clone(applicationProtocols);
        for (String entry : check)
        {
            if (TlsUtils.isNullOrEmpty(entry))
            {
                throw new IllegalArgumentException("'applicationProtocols' entries cannot be null or empty strings");
            }
        }

        this.applicationProtocols = check;
    }

    public String[] getCipherSuites()
    {
        return TlsUtils.clone(cipherSuites);
    }

    public void setCipherSuites(String[] cipherSuites)
    {
        this.cipherSuites = TlsUtils.clone(cipherSuites);
    }

    public String[] getProtocols()
    {
        return TlsUtils.clone(protocols);
    }

    public void setProtocols(String[] protocols)
    {
        this.protocols = TlsUtils.clone(protocols);
    }

    public boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth)
    {
        this.wantClientAuth = wantClientAuth;
        this.needClientAuth = false;
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

    public String getEndpointIdentificationAlgorithm()
    {
        return endpointIdentificationAlgorithm;
    }

    public void setEndpointIdentificationAlgorithm(String endpointIdentificationAlgorithm)
    {
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
    }

    public BCAlgorithmConstraints getAlgorithmConstraints()
    {
        return algorithmConstraints;
    }

    public void setAlgorithmConstraints(BCAlgorithmConstraints algorithmConstraints)
    {
        this.algorithmConstraints = algorithmConstraints;
    }

    public void setServerNames(List<BCSNIServerName> serverNames)
    {
        if (serverNames == null)
        {
            this.serverNames = null;
        }
        else
        {
            List<BCSNIServerName> copy = copyList(serverNames);

            Set<Integer> types = new HashSet<Integer>();
            for (BCSNIServerName serverName : copy)
            {
                int type = serverName.getType();
                if (!types.add(type))
                {
                    throw new IllegalArgumentException("Found duplicate SNI server name entry of type " + type);
                }
            }

            this.serverNames = copy;
        }
    }

    public List<BCSNIServerName> getServerNames()
    {
        return copyList(this.serverNames);
    }

    public void setSNIMatchers(Collection<BCSNIMatcher> sniMatchers)
    {
        if (sniMatchers == null)
        {
            this.sniMatchers = null;
        }
        else
        {
            List<BCSNIMatcher> copy = copyList(sniMatchers);

            Set<Integer> types = new HashSet<Integer>();
            for (BCSNIMatcher sniMatcher : copy)
            {
                int type = sniMatcher.getType();
                if (!types.add(type))
                {
                    throw new IllegalArgumentException("Found duplicate SNI matcher entry of type " + type);
                }
            }

            this.sniMatchers = copy;
        }
    }

    public Collection<BCSNIMatcher> getSNIMatchers()
    {
        return copyList(this.sniMatchers);
    }

    public void setUseCipherSuitesOrder(boolean useCipherSuitesOrder)
    {
        this.useCipherSuitesOrder = useCipherSuitesOrder;
    }

    public boolean getUseCipherSuitesOrder()
    {
        return useCipherSuitesOrder;
    }
}
