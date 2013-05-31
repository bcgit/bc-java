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
public class BlockCipherMonteCarloTest
    extends SimpleTest
{
    int                 id;
    int                 iterations;
    BlockCipher         engine;
    CipherParameters    param;
    byte[]              input;
    byte[]              output;

    public BlockCipherMonteCarloTest(
        int                 id,
        int                 iterations,
        BlockCipher         engine,
        CipherParameters    param,
        String              input,
        String              output)
    {
        this.id = id;
        this.iterations = iterations;
        this.engine = engine;
        this.param = param;
        this.input = Hex.decode(input);
        this.output = Hex.decode(output);
    }

    public String getName()
    {
        return engine.getAlgorithmName() + " Monte Carlo Test " + id;
    }

    public void performTest()
        throws Exception
    {
        BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

        cipher.init(true, param);

        byte[]  out = new byte[input.length];

        System.arraycopy(input, 0, out, 0, out.length);

        for (int i = 0; i != iterations; i++)
        {
            int len1 = cipher.processBytes(out, 0, out.length, out, 0);

            cipher.doFinal(out, len1);
        }

        if (!areEqual(out, output))
        {
            fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        cipher.init(false, param);

        for (int i = 0; i != iterations; i++)
        {
            int len1 = cipher.processBytes(out, 0, out.length, out, 0);

            cipher.doFinal(out, len1);
        }

        if (!areEqual(input, out))
        {
            fail("failed reversal");
        }
    }
}
