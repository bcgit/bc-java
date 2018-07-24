package org.bouncycastle.crypto.tls;

import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.params.DHParameters;

public class DefaultTlsDHVerifier
    implements TlsDHVerifier
{
    public static final int DEFAULT_MINIMUM_PRIME_BITS = 2048;

    protected static final Vector DEFAULT_GROUPS = new Vector();

    private static void addDefaultGroup(DHParameters dhParameters)
    {
        DEFAULT_GROUPS.addElement(dhParameters);
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

    // Vector is (DHParameters)
    protected Vector groups;
    protected int minimumPrimeBits;

    /**
     * Accept various standard DH groups with 'P' at least {@link #DEFAULT_MINIMUM_PRIME_BITS} bits.
     */
    public DefaultTlsDHVerifier()
    {
        this(DEFAULT_MINIMUM_PRIME_BITS);
    }

    /**
     * Accept various standard DH groups with 'P' at least the specified number of bits.
     */
    public DefaultTlsDHVerifier(int minimumPrimeBits)
    {
        this(DEFAULT_GROUPS, minimumPrimeBits);
    }

    /**
     * Accept a custom set of group parameters, subject to a minimum bitlength for 'P'.
     * 
     * @param groups a {@link Vector} of acceptable {@link DHParameters}.
     */
    public DefaultTlsDHVerifier(Vector groups, int minimumPrimeBits)
    {
        this.groups = groups;
        this.minimumPrimeBits = minimumPrimeBits;
    }

    public boolean accept(DHParameters dhParameters)
    {
        return checkMinimumPrimeBits(dhParameters) && checkGroup(dhParameters);
    }

    public int getMinimumPrimeBits()
    {
        return minimumPrimeBits;
    }

    protected boolean areGroupsEqual(DHParameters a, DHParameters b)
    {
        return a == b || (areParametersEqual(a.getP(), b.getP()) && areParametersEqual(a.getG(), b.getG()));
    }

    protected boolean areParametersEqual(BigInteger a, BigInteger b)
    {
        return a == b || a.equals(b);
    }

    protected boolean checkGroup(DHParameters dhParameters)
    {
        for (int i = 0; i < groups.size(); ++i)
        {
            if (areGroupsEqual(dhParameters, (DHParameters)groups.elementAt(i)))
            {
                return true;
            }
        }
        return false;
    }

    protected boolean checkMinimumPrimeBits(DHParameters dhParameters)
    {
        return dhParameters.getP().bitLength() >= getMinimumPrimeBits();
    }
}
