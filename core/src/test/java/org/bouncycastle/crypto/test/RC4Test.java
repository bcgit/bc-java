package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * RC4 Test
 */
public class RC4Test
    extends SimpleTest
{
    StreamCipherVectorTest[] tests =
    {
        new StreamCipherVectorTest(0, new RC4Engine(),
                new KeyParameter(Hex.decode("0123456789ABCDEF")),
                "4e6f772069732074", "3afbb5c77938280d"),
        new StreamCipherVectorTest(0, new RC4Engine(),
                new KeyParameter(Hex.decode("0123456789ABCDEF")),
                "68652074696d6520", "1cf1e29379266d59"),
        new StreamCipherVectorTest(0, new RC4Engine(),
                new KeyParameter(Hex.decode("0123456789ABCDEF")),
                "666f7220616c6c20", "12fbb0c771276459")
    };

    public String getName()
    {
        return "RC4";
    }

    public void performTest()
    {
        for (int i = 0; i != tests.length; i++)
        {
            tests[i].performTest();
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new RC4Test());
    }
}
