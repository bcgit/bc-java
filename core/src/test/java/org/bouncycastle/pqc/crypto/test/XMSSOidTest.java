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
        assertEquals(0x01000001, xmssOid.getOid());
        assertEquals("XMSS_SHA2-256_W16_H10", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 16, 67, 16);
        assertEquals(0x02000002, xmssOid.getOid());
        assertEquals("XMSS_SHA2-256_W16_H16", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-256", 32, 16, 67, 20);
        assertEquals(0x03000003, xmssOid.getOid());
        assertEquals("XMSS_SHA2-256_W16_H20", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-512", 64, 16, 131, 10);
        assertEquals(0x04000004, xmssOid.getOid());
        assertEquals("XMSS_SHA2-512_W16_H10", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-512", 64, 16, 131, 16);
        assertEquals(0x05000005, xmssOid.getOid());
        assertEquals("XMSS_SHA2-512_W16_H16", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHA-512", 64, 16, 131, 20);
        assertEquals(0x06000006, xmssOid.getOid());
        assertEquals("XMSS_SHA2-512_W16_H20", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE128", 32, 16, 67, 10);
        assertEquals(0x07000007, xmssOid.getOid());
        assertEquals("XMSS_SHAKE128_W16_H10", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE128", 32, 16, 67, 16);
        assertEquals(0x08000008, xmssOid.getOid());
        assertEquals("XMSS_SHAKE128_W16_H16", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE128", 32, 16, 67, 20);
        assertEquals(0x09000009, xmssOid.getOid());
        assertEquals("XMSS_SHAKE128_W16_H20", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE256", 64, 16, 131, 10);
        assertEquals(0x0a00000a, xmssOid.getOid());
        assertEquals("XMSS_SHAKE256_W16_H10", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE256", 64, 16, 131, 16);
        assertEquals(0x0b00000b, xmssOid.getOid());
        assertEquals("XMSS_SHAKE256_W16_H16", xmssOid.toString());
        xmssOid = DefaultXMSSOid.lookup("SHAKE256", 64, 16, 131, 20);
        assertEquals(0x0c00000c, xmssOid.getOid());
        assertEquals("XMSS_SHAKE256_W16_H20", xmssOid.toString());
    }
}
