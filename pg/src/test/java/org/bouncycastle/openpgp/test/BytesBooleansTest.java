package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.sig.PrimaryUserID;

import junit.framework.TestCase;

public class BytesBooleansTest
    extends TestCase
{
    public void testParseFalse()
    {
        PrimaryUserID primaryUserID = new PrimaryUserID(true, false);

        byte[] bFalse = primaryUserID.getData();
        assertEquals(1, bFalse.length);
        assertEquals(0, bFalse[0]);
        assertFalse(primaryUserID.isPrimaryUserID());
    }

    public void testParseTrue()
    {
        PrimaryUserID primaryUserID = new PrimaryUserID(true, true);

        byte[] bTrue = primaryUserID.getData();

        assertEquals(1, bTrue.length);
        assertEquals(1, bTrue[0]);
        assertTrue(primaryUserID.isPrimaryUserID());
    }

    public void testParseTooShort()
    {
        PrimaryUserID primaryUserID = new PrimaryUserID(true, false, new byte[0]);
        byte[] bTooShort = primaryUserID.getData();
        try
        {
            primaryUserID.isPrimaryUserID();
            fail("Should throw.");
        }
        catch (IllegalStateException e)
        {
            // expected.
        }
    }

    public void testParseTooLong()
    {
        PrimaryUserID primaryUserID = new PrimaryUserID(true, false, new byte[42]);
        byte[] bTooLong = primaryUserID.getData();

        try
        {
            primaryUserID.isPrimaryUserID();
            fail("Should throw.");
        }
        catch (IllegalStateException e)
        {
            // expected.
        }
    }
}
