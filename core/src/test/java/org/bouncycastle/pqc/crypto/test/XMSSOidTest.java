package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.pqc.crypto.xmss.DefaultXMSSOid;

/**
 * Test cases for {@link DefaultXMSSOid} class.
 */
public class XMSSOidTest
    extends TestCase
{

    public void testXMSSOidException1()
    {
        DefaultXMSSOid xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 16, 67, -1);
        assertEquals(xmssOid, null);
    }

    public void testXMSSOidException2()
    {
        DefaultXMSSOid xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 16, 67, 8);
        assertEquals(xmssOid, null);
    }

    public void testXMSSOidException3()
    {
        DefaultXMSSOid xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 4, 67, 10);
        assertEquals(xmssOid, null);
    }

    public void testXMSSOid()
    {
        DefaultXMSSOid xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 16, 67, 10);
        assertEquals(0x00000001, xmssOid.getOid());
        assertEquals("XMSS_SHA2_10_256", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 16, 67, 16);
        assertEquals(0x00000002, xmssOid.getOid());
        assertEquals("XMSS_SHA2_16_256", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 16, 67, 20);
        assertEquals(0x00000003, xmssOid.getOid());
        assertEquals("XMSS_SHA2_20_256", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-512", 64, 16, 131, 10);
        assertEquals(0x00000004, xmssOid.getOid());
        assertEquals("XMSS_SHA2_10_512", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-512", 64, 16, 131, 16);
        assertEquals(0x00000005, xmssOid.getOid());
        assertEquals("XMSS_SHA2_16_512", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-512", 64, 16, 131, 20);
        assertEquals(0x00000006, xmssOid.getOid());
        assertEquals("XMSS_SHA2_20_512", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE128", 32, 16, 67, 10);
        assertEquals(0x00000007, xmssOid.getOid());
        assertEquals("XMSS_SHAKE_10_256", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE128", 32, 16, 67, 16);
        assertEquals(0x00000008, xmssOid.getOid());
        assertEquals("XMSS_SHAKE_16_256", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE128", 32, 16, 67, 20);
        assertEquals(0x00000009, xmssOid.getOid());
        assertEquals("XMSS_SHAKE_20_256", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE256", 64, 16, 131, 10);
        assertEquals(0x0000000a, xmssOid.getOid());
        assertEquals("XMSS_SHAKE_10_512", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE256", 64, 16, 131, 16);
        assertEquals(0x0000000b, xmssOid.getOid());
        assertEquals("XMSS_SHAKE_16_512", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE256", 64, 16, 131, 20);
        assertEquals(0x0000000c, xmssOid.getOid());
        assertEquals("XMSS_SHAKE_20_512", xmssOid.toString());
    }
}
