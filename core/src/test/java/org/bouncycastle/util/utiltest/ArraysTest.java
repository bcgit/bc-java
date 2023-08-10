package org.bouncycastle.util.utiltest;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;

public class ArraysTest
    extends TestCase
{
    public void testConcatenate()
    {
        assertNull(Arrays.concatenate((byte[])null, (byte[])null));
        assertNull(Arrays.concatenate((int[])null, (int[])null));
    }

    public void testCopyOfRange()
    {
        try
        {
            Arrays.copyOfRange(new byte[10], 5, 2);
            fail("no exception");
        }
        catch (Exception e)
        {
            assertEquals("5 > 2", e.getMessage());
        }
    }
}
