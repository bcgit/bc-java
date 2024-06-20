package org.bouncycastle.openpgp.test;

import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.util.test.SimpleTest;

public class PGPPaddingTest
        extends SimpleTest
{
    @Override
    public String getName()
    {
        return "PGPPaddingTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        randomPaddingIsInBounds();
        fixedLenPaddingIsCorrectLength();
        negativePaddingLengthThrows();
        zeroPaddingLengthThrows();
    }

    private void randomPaddingIsInBounds()
    {
        for (int i = 0; i < 10; i++)
        {
            PGPPadding padding = new PGPPadding();
            int len = padding.getPadding().length;
            isTrue("Padding length exceeds bounds. Min: " + PGPPadding.MIN_PADDING_LEN +
                            ", Max: " + PGPPadding.MAX_PADDING_LEN + ", Actual: " + len ,
                    len >= PGPPadding.MIN_PADDING_LEN && len <= PGPPadding.MAX_PADDING_LEN);
        }
    }

    private void fixedLenPaddingIsCorrectLength()
    {
        PGPPadding padding = new PGPPadding(42);
        isEquals("Padding length mismatch", 42, padding.getPadding().length);
    }

    private void negativePaddingLengthThrows()
    {
        testException(null, "IllegalArgumentException", () -> new PGPPadding(-1));
    }

    private void zeroPaddingLengthThrows()
    {
        testException(null, "IllegalArgumentException", () -> new PGPPadding(0));
    }

    public static void main(String[] args)
    {
        runTest(new PGPPaddingTest());
    }
}
