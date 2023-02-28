package org.bouncycastle.openpgp.test;

import java.util.Random;

import org.bouncycastle.bcpg.CRC24;
import org.bouncycastle.bcpg.FastCRC24;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class CRC24Test
    extends SimpleTest
{

    private static final byte[] TEST_VECTOR_1 = "Hello, World!\n".getBytes();
    private static final byte[] TEST_VECTOR_2 = new byte[256];
    private static final byte[] LARGE_RANDOM = new byte[3 * 1024 * 1024]; // 3 MB

    static
    {
        Arrays.fill(TEST_VECTOR_2, 0, TEST_VECTOR_2.length - 1, (byte)12);
        new Random().nextBytes(LARGE_RANDOM);
    }

    public static void main(String[] args)
    {
        runTest(new CRC24Test());
    }

    @Override
    public String getName()
    {
        return "CRC24Test";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testDefaultImpl();
        testFastImpl();

        performanceTest();
    }

    public void testDefaultImpl()
    {
        CRC24 crc = new CRC24();
        testCrcImplementationAgainstTestVectors(crc);
    }

    public void testFastImpl()
    {
        CRC24 crc = new FastCRC24();
        testCrcImplementationAgainstTestVectors(crc);
    }

    private void testCrcImplementationAgainstTestVectors(CRC24 crc)
    {
        isEquals("CRC implementation has wrong initial value", 0x0b704ce, crc.getValue());

        crc.reset();
        isEquals("CRC implementation reset to wrong value", 0x0b704ce, crc.getValue());

        crc.reset();
        for (int i = 0; i != TEST_VECTOR_1.length; i++)
        {
            crc.update(TEST_VECTOR_1[i]);
        }
        isEquals("Wrong CRC sum calculated", 0x71cee5, crc.getValue());

        crc.reset();
        for (int i = 0; i != TEST_VECTOR_2.length; i++)
        {
            crc.update(TEST_VECTOR_2[i]);
        }
        isEquals("Wrong CRC sum calculated", 0x1938a3, crc.getValue());
    }

    public void performanceTest()
    {
        CRC24 defaultImpl = new CRC24();

        CRC24 fastImpl = new FastCRC24();
        // "Warm up" to initialize lookup table
        fastImpl.update(0);
        fastImpl.reset();

        long start = System.currentTimeMillis();

        for (int j = 0; j < 100; ++j)
        {
            for (int i = 0; i != LARGE_RANDOM.length; i += 3)
            {
                defaultImpl.update3(LARGE_RANDOM, i);
            }
        }
        int defVal = defaultImpl.getValue();
        long afterDefault = System.currentTimeMillis();

        for (int j = 0; j < 100; ++j)
        {
            for (int i = 0; i != LARGE_RANDOM.length; i += 3)
            {
                fastImpl.update3(LARGE_RANDOM, i);
            }
        }
        int fastVal = fastImpl.getValue();
        long afterFast = System.currentTimeMillis();

        isEquals("Calculated value of default and fast CRC-24 implementations diverges", defVal, fastVal);
        long defDuration = afterDefault - start;
        System.out.println("Default Implementation: " + defDuration / 1000 + "s" + defDuration % 1000);

        long fastDuration = afterFast - afterDefault;
        System.out.println("Fast Implementation: " + fastDuration / 1000 + "s" + fastDuration % 1000);

    }
}
