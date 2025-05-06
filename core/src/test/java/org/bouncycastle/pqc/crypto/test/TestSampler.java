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
        return !isFull && shouldSkip(Integer.parseInt(count));
    }

    boolean skipTest(int count)
    {
        return !isFull && shouldSkip(count);
    }

    private boolean shouldSkip(int count)
    {
        return count != 0 && ((count + offSet) % 9 != 0);
    }
}
