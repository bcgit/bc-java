package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * SM4 tester, vectors from <a href="http://eprint.iacr.org/2008/329.pdf">http://eprint.iacr.org/2008/329.pdf</a>
 */
public class SM4Test
    extends CipherTest
{
    static SimpleTest[]  tests = {
        new BlockCipherVectorTest(0, new SM4Engine(),
            new KeyParameter(Hex.decode("0123456789abcdeffedcba9876543210")),
            "0123456789abcdeffedcba9876543210",
            "681edf34d206965e86b3e94f536e4246")
            };

    SM4Test()
    {
        super(tests, new SM4Engine(), new KeyParameter(new byte[16]));
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        test1000000();
    }

    private void test1000000()
    {
        byte[] plain = Hex.decode("0123456789abcdeffedcba9876543210");
        byte[] key = Hex.decode("0123456789abcdeffedcba9876543210");
        byte[] cipher = Hex.decode("595298c7c6fd271f0402f804c33d3f66");
        byte[] buf = new byte[16];

        BlockCipher engine = new SM4Engine();

        engine.init(true, new KeyParameter(key));

        System.arraycopy(plain, 0, buf, 0, buf.length);

        for (int i = 0; i != 1000000; i++)
        {
            engine.processBlock(buf, 0, buf, 0);
        }

        if (!areEqual(cipher, buf))
        {
            fail("1000000 encryption test failed");
        }

        engine.init(false, new KeyParameter(key));

        for (int i = 0; i != 1000000; i++)
        {
            engine.processBlock(buf, 0, buf, 0);
        }

        if (!areEqual(plain, buf))
        {
            fail("1000000 decryption test failed");
        }
    }

    public String getName()
    {
        return "SM4";
    }

    public static void main(
        String[]    args)
    {
        runTest(new SM4Test());
    }
}
