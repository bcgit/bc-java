package org.bouncycastle.crypto.tls;

import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.params.SRP6GroupParameters;

public class DefaultTlsSRPGroupVerifier
    implements TlsSRPGroupVerifier
{
    protected static final Vector DEFAULT_GROUPS = new Vector();

    static
    {
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_1024);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_1536);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_2048);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_3072);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_4096);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_6144);
        DEFAULT_GROUPS.addElement(SRP6StandardGroups.rfc5054_8192);
    }

    // Vector is (SRP6GroupParameters)
    protected Vector groups;

    /**
     * Accept only the group parameters specified in RFC 5054 Appendix A.
     */
    public DefaultTlsSRPGroupVerifier()
    {
        this(DEFAULT_GROUPS);
    }

    /**
     * Specify a custom set of acceptable group parameters.
     * 
     * @param groups a {@link Vector} of acceptable {@link SRP6GroupParameters}
     */
    public DefaultTlsSRPGroupVerifier(Vector groups)
    {
        this.groups = groups;
    }

    public boolean accept(SRP6GroupParameters group)
    {
        for (int i = 0; i < groups.size(); ++i)
        {
            if (areGroupsEqual(group, (SRP6GroupParameters)groups.elementAt(i)))
            {
                return true;
            }
        }
        return false;
    }

    protected boolean areGroupsEqual(SRP6GroupParameters a, SRP6GroupParameters b)
    {
        return a == b || (areParametersEqual(a.getN(), b.getN()) && areParametersEqual(a.getG(), b.getG()));
    }
    
    protected boolean areParametersEqual(BigInteger a, BigInteger b)
    {
        return a == b || a.equals(b);
    }
}
