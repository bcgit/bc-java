package org.bouncycastle.pqc.crypto.test;

import java.util.Random;

import org.bouncycastle.util.Properties;

class TestSampler
{
    private final boolean isFull;
    private final int offSet;

    TestSampler()
    {
        isFull = Properties.isOverrideSet("test.full");

        Random random = new Random(System.currentTimeMillis());

        this.offSet = random.nextInt(10);
    }

    boolean skipTest(String count)
    {
        int c = Integer.parseInt(count);
        return !isFull && c != 0 && ((c + offSet) % 9 != 0);
    }

    boolean skipTest(int count)
    {
        return !isFull && count != 0 && ((count + offSet) % 9 != 0);
    }
}
