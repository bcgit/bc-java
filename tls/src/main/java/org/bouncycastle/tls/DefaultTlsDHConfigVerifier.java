package org.bouncycastle.tls;

import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.DHStandardGroups;
import org.bouncycastle.tls.crypto.TlsDHConfig;

public class DefaultTlsDHConfigVerifier
    implements TlsDHConfigVerifier
{
    public static final int DEFAULT_MINIMUM_PRIME_BITS = 1024;

    protected static final Vector DEFAULT_GROUPS = new Vector();

    private static void addDefaultGroup(DHGroup dhParameters)
    {
        DEFAULT_GROUPS.addElement(TlsDHUtils.selectDHConfig(dhParameters));
    }

    static
    {
        addDefaultGroup(DHStandardGroups.rfc3526_1536);
        addDefaultGroup(DHStandardGroups.rfc3526_2048);
        addDefaultGroup(DHStandardGroups.rfc3526_3072);
        addDefaultGroup(DHStandardGroups.rfc3526_4096);
        addDefaultGroup(DHStandardGroups.rfc3526_6144);
        addDefaultGroup(DHStandardGroups.rfc3526_8192);

        addDefaultGroup(DHStandardGroups.rfc5996_768);
        addDefaultGroup(DHStandardGroups.rfc5996_1024);
    }

    // Vector is (TlsDHConfig)
    protected Vector groups;
    protected int minimumPrimeBits;

    /**
     * Accept only various standard DH groups with 'P' at least {@link #DEFAULT_MINIMUM_PRIME_BITS} bits.
     */
    public DefaultTlsDHConfigVerifier()
    {
        this(DEFAULT_MINIMUM_PRIME_BITS);
    }

    /**
     * Accept only various standard DH groups with 'P' at least the specified number of bits.
     */
    public DefaultTlsDHConfigVerifier(int minimumPrimeBits)
    {
        this(DEFAULT_GROUPS, minimumPrimeBits);
    }

    /**
     * Specify a custom set of acceptable group parameters, and a minimum bitlength for 'P'
     * 
     * @param groups a {@link Vector} of acceptable {@link TlsDHConfig}
     */
    public DefaultTlsDHConfigVerifier(Vector groups, int minimumPrimeBits)
    {
        this.groups = groups;
        this.minimumPrimeBits = minimumPrimeBits;
    }

    public boolean accept(TlsDHConfig dhConfig)
    {
        if (dhConfig.getExplicitPG()[0].bitLength() < getMinimumPrimeBits())
        {
            return false;
        }
        for (int i = 0; i < groups.size(); ++i)
        {
            if (areGroupsEqual(dhConfig, (TlsDHConfig)groups.elementAt(i)))
            {
                return true;
            }
        }
        return false;
    }

    public int getMinimumPrimeBits()
    {
        return minimumPrimeBits;
    }

    protected boolean areGroupsEqual(TlsDHConfig a, TlsDHConfig b)
    {
        return a == b || (areParametersEqual(a.getExplicitPG(), b.getExplicitPG()));
    }

    protected boolean areParametersEqual(BigInteger[] pgA, BigInteger[] pgB)
    {
        return pgA == pgB || (areParametersEqual(pgA[0], pgB[0]) && areParametersEqual(pgA[1], pgB[1]));
    }

    protected boolean areParametersEqual(BigInteger a, BigInteger b)
    {
        return a == b || a.equals(b);
    }
}
