package org.bouncycastle.tls;

import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.DHStandardGroups;

public class DefaultTlsDHGroupVerifier
    implements TlsDHGroupVerifier
{
    public static final int DEFAULT_MINIMUM_PRIME_BITS = 2048;

    protected static final Vector DEFAULT_GROUPS = new Vector();

    private static void addDefaultGroup(DHGroup dhGroup)
    {
        DEFAULT_GROUPS.addElement(dhGroup);
    }

    static
    {
        /*
         * These 10 standard groups are those specified in NIST SP 800-56A Rev. 3 Appendix D. Make
         * sure to consider the impact on BCJSSE's FIPS mode and/or usage with the BCFIPS provider
         * before modifying this list.
         */

        addDefaultGroup(DHStandardGroups.rfc3526_2048);
        addDefaultGroup(DHStandardGroups.rfc3526_3072);
        addDefaultGroup(DHStandardGroups.rfc3526_4096);
        addDefaultGroup(DHStandardGroups.rfc3526_6144);
        addDefaultGroup(DHStandardGroups.rfc3526_8192);

        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe2048);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe3072);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe4096);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe6144);
        addDefaultGroup(DHStandardGroups.rfc7919_ffdhe8192);
    }

    // Vector is (DHGroup)
    protected Vector groups;
    protected int minimumPrimeBits;

    /**
     * Accept named groups and various standard DH groups with 'P' at least {@link #DEFAULT_MINIMUM_PRIME_BITS} bits.
     */
    public DefaultTlsDHGroupVerifier()
    {
        this(DEFAULT_MINIMUM_PRIME_BITS);
    }

    /**
     * Accept named groups and various standard DH groups with 'P' at least the specified number of bits.
     */
    public DefaultTlsDHGroupVerifier(int minimumPrimeBits)
    {
        this(DEFAULT_GROUPS, minimumPrimeBits);
    }

    /**
     * Accept named groups and a custom set of group parameters, subject to a minimum bitlength for 'P'.
     * 
     * @param groups a {@link Vector} of acceptable {@link DHGroup}s.
     */
    public DefaultTlsDHGroupVerifier(Vector groups, int minimumPrimeBits)
    {
        this.groups = groups;
        this.minimumPrimeBits = minimumPrimeBits;
    }

    public boolean accept(DHGroup dhGroup)
    {
        return checkMinimumPrimeBits(dhGroup) && checkGroup(dhGroup);
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

    protected boolean checkGroup(DHGroup dhGroup)
    {
        for (int i = 0; i < groups.size(); ++i)
        {
            if (areGroupsEqual(dhGroup, (DHGroup)groups.elementAt(i)))
            {
                return true;
            }
        }
        return false;
    }

    protected boolean checkMinimumPrimeBits(DHGroup dhGroup)
    {
        return dhGroup.getP().bitLength() >= getMinimumPrimeBits();
    }
}
