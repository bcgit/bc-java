package org.bouncycastle.math.ec.custom.sec.test;


import java.util.Arrays;

import org.bouncycastle.math.ec.custom.sec.SecP128R1Field;
import org.bouncycastle.math.raw.Nat128;

import junit.framework.TestCase;

public class SecP128R1FieldTest extends TestCase
{
    public void test_GitHub566()
    {
        int[] x = new int[]{ 0x4B1E2F5E, 0x09E29D21, 0xA58407ED, 0x6FC3C7CF };
        int[] y = new int[]{ 0x2FFE8892, 0x55CA61CA, 0x0AF780B5, 0x4BD7B797 };
        int[] z = Nat128.create();

        SecP128R1Field.multiply(x, y, z);

        int[] expected = new int[]{ 0x01FFFF01, 0, 0, 0 };
        assertTrue(Arrays.equals(expected, z));
    }

    public void testReduce32()
    {
        int[] z = Nat128.create();
        Arrays.fill(z, 0xFFFFFFFF);
        SecP128R1Field.reduce32(0xFFFFFFFF, z);

        int[] expected = new int[]{ 1, 1, 0, 4 };
        assertTrue(Arrays.equals(expected, z));
    }
}
