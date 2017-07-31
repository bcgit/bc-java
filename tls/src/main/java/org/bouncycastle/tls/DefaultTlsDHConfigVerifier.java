package org.bouncycastle.tls;

import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.DHStandardGroups;
import org.bouncycastle.tls.crypto.TlsDHConfig;

public class DefaultTlsDHConfigVerifier
    implements TlsDHConfigVerifier
{
    public static final int DEFAULT_MINIMUM_PRIME_BITS = 2048;

    protected static final Vector DEFAULT_GROUPS = new Vector();

    private static void addDefaultGroup(DHGroup dhGroup)
    {
        DEFAULT_GROUPS.addElement(dhGroup);
    }

    static
    {
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe2048);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe3072);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe4096);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe6144);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe8192);

        addDefaultGroup(DHStandardGroups.rfc3526_1536);
        addDefaultGroup(DHStandardGroups.rfc3526_2048);
        addDefaultGroup(DHStandardGroups.rfc3526_3072);
        addDefaultGroup(DHStandardGroups.rfc3526_4096);
        addDefaultGroup(DHStandardGroups.rfc3526_6144);
        addDefaultGroup(DHStandardGroups.rfc3526_8192);
    }

    // Vector is (DHGroup)
    protected Vector groups;
    protected int minimumPrimeBits;

    /**
     * Accept named groups and various standard DH groups with 'P' at least {@link #DEFAULT_MINIMUM_PRIME_BITS} bits.
     */
    public DefaultTlsDHConfigVerifier()
    {
        this(DEFAULT_MINIMUM_PRIME_BITS);
    }

    /**
     * Accept named groups and various standard DH groups with 'P' at least the specified number of bits.
     */
    public DefaultTlsDHConfigVerifier(int minimumPrimeBits)
    {
        this(DEFAULT_GROUPS, minimumPrimeBits);
    }

    /**
     * Accept named groups and a custom set of group parameters, subject to a minimum bitlength for 'P'.
     * 
     * @param groups a {@link Vector} of acceptable {@link DHGroup}s.
     */
    public DefaultTlsDHConfigVerifier(Vector groups, int minimumPrimeBits)
    {
        this.groups = groups;
        this.minimumPrimeBits = minimumPrimeBits;
    }

    public boolean accept(TlsDHConfig dhConfig)
    {
        return checkMinimumPrimeBits(dhConfig) && checkGroup(dhConfig);
    }

    public int getMinimumPrimeBits()
    {
        return minimumPrimeBits;
    }

    protected boolean areGroupsEqual(DHGroup a, DHGroup b)
    {
        return a == b || (areParametersEqual(a.getP(), b.getP()) && areParametersEqual(a.getG(), b.getG()));
    }

    protected boolean areParametersEqual(BigInteger a, BigInteger b)
    {
        return a == b || a.equals(b);
    }

    protected boolean checkGroup(TlsDHConfig dhConfig)
    {
        if (NamedGroup.refersToASpecificFiniteField(dhConfig.getNamedGroup()))
        {
            return true;
        }

        DHGroup explicitGroup = dhConfig.getExplicitGroup();
        for (int i = 0; i < groups.size(); ++i)
        {
            if (areGroupsEqual(explicitGroup, (DHGroup)groups.elementAt(i)))
            {
                return true;
            }
        }
        return false;
    }

    protected boolean checkMinimumPrimeBits(TlsDHConfig dhConfig)
    {
        int bits = getMinimumPrimeBits();

        int namedGroup = dhConfig.getNamedGroup();
        if (namedGroup >= 0)
        {
            return NamedGroup.getFiniteFieldBits(namedGroup) >= bits;
        }

        DHGroup explicitGroup = dhConfig.getExplicitGroup();
        return explicitGroup.getP().bitLength() >= bits;
    }
}
