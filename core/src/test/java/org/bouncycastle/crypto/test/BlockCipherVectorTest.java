package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * a basic test that takes a cipher, key parameter, and an input
 * and output string. This test wraps the engine in a buffered block
 * cipher with padding disabled.
 */
public class BlockCipherVectorTest
    extends SimpleTest
{
    int                 id;
    BlockCipher         engine;
    CipherParameters    param;
    byte[]              input;
    byte[]              output;

    public BlockCipherVectorTest(
        int                 id,
        BlockCipher         engine,
        CipherParameters    param,
        String              input,
        String              output)
    {
        this.id = id;
        this.engine = engine;
        this.param = param;
        this.input = Hex.decode(input);
        this.output = Hex.decode(output);
    }

    public String getName()
    {
        return engine.getAlgorithmName() + " Vector Test " + id;
    }

    public void performTest()
        throws Exception
    {
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

        cipher.init(true, param);

        byte[]  out = new byte[input.length];

        int len1 = cipher.processBytes(input, 0, input.length, out, 0);

        cipher.doFinal(out, len1);

        if (!areEqual(out, output))
        {
            fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        cipher.init(false, param);

        int len2 = cipher.processBytes(output, 0, output.length, out, 0);

        cipher.doFinal(out, len2);

        if (!areEqual(input, out))
        {
            System.out.println(" got " + new String(Hex.encode(out)));

            fail("failed reversal - " + "expected " + new String(Hex.encode(input)));
        }
    }
}
