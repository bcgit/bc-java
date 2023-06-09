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

    private String[] cipherSuites;
    private String[] protocols;
    private boolean wantClientAuth;
    private boolean needClientAuth;
    private String endpointIdentificationAlgorithm;
    private BCAlgorithmConstraints algorithmConstraints;
    private List<BCSNIServerName> serverNames;
    private List<BCSNIMatcher> sniMatchers;
    private boolean useCipherSuitesOrder;
    private boolean enableRetransmissions = true;
    private int maximumPacketSize = 0;
    private String[] applicationProtocols = TlsUtils.EMPTY_STRINGS;
    private String[] signatureSchemes = null;
    private String[] namedGroups = null;

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

    public List<BCSNIServerName> getServerNames()
    {
        return copyList(this.serverNames);
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

    public Collection<BCSNIMatcher> getSNIMatchers()
    {
        return copyList(this.sniMatchers);
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

    public boolean getUseCipherSuitesOrder()
    {
        return useCipherSuitesOrder;
    }

    public void setUseCipherSuitesOrder(boolean useCipherSuitesOrder)
    {
        this.useCipherSuitesOrder = useCipherSuitesOrder;
    }

    public boolean getEnableRetransmissions()
    {
        return enableRetransmissions;
    }

    public void setEnableRetransmissions(boolean enableRetransmissions)
    {
        this.enableRetransmissions = enableRetransmissions;
    }

    public int getMaximumPacketSize()
    {
        return maximumPacketSize;
    }

    public void setMaximumPacketSize(int maximumPacketSize)
    {
        if (maximumPacketSize < 0)
        {
            throw new IllegalArgumentException("The maximum packet size cannot be negative");
        }

        this.maximumPacketSize = maximumPacketSize;
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

    public String[] getSignatureSchemes()
    {
        return TlsUtils.clone(signatureSchemes);
    }

    public void setSignatureSchemes(String[] signatureSchemes)
    {
        String[] check = null;

        if (signatureSchemes != null)
        {
            check = TlsUtils.clone(signatureSchemes);
            for (String entry : check)
            {
                if (TlsUtils.isNullOrEmpty(entry))
                {
                    throw new IllegalArgumentException("'signatureSchemes' entries cannot be null or empty strings");
                }
            }
        }

        this.signatureSchemes = check;
    }

    public String[] getNamedGroups()
    {
        return TlsUtils.clone(namedGroups);
    }

    public void setNamedGroups(String[] namedGroups)
    {
        String[] check = null;

        if (namedGroups != null)
        {
            check = TlsUtils.clone(namedGroups);
            HashSet<String> seenEntries = new HashSet<String>();
            for (String entry : check)
            {
                if (TlsUtils.isNullOrEmpty(entry))
                {
                    throw new IllegalArgumentException("'namedGroups' entries cannot be null or empty strings");
                }

                if (!seenEntries.add(entry))
                {
                    throw new IllegalArgumentException("'namedGroups' contains duplicate entry: " + entry);
                }
            }
        }

        this.namedGroups = check;
    }
}
