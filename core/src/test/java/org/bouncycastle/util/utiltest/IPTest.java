package org.bouncycastle.util.utiltest;

import junit.framework.TestCase;
import org.bouncycastle.util.IPAddress;

public class IPTest
    extends TestCase
{

    private static final String validIP4v[] = new String[]
    { "0.0.0.0", "255.255.255.255", "192.168.0.0" };

    private static final String invalidIP4v[] = new String[]
    { "0.0.0.0.1", "256.255.255.255", "1", "A.B.C", "1:.4.6.5" };

    private static final String validIP6v[] = new String[]
    { "0:0:0:0:0:0:0:0", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
            "0:1:2:3:FFFF:5:FFFF:1" };

    private static final String invalidIP6v[] = new String[]
    { "0.0.0.0:1", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFFF" };

    private void testIP(String[] valid, String[] invalid)
    {
        for (int i = 0; i < valid.length; i++)
        {
            if (!IPAddress.isValid(valid[i]))
            {
                fail("Valid input string not accepted: " + valid[i] + ".");
            }
        }
        for (int i = 0; i < invalid.length; i++)
        {
            if (IPAddress.isValid(invalid[i]))
            {
                fail("Invalid input string accepted: " + invalid[i] + ".");
            }
        }
    }

    public String getName()
    {
        return "IPTest";
    }

    public void testIPv4()
    {
        testIP(validIP4v, invalidIP4v);
    }

    public void testIPv6()
    {
        testIP(validIP6v, invalidIP6v);
    }
}
