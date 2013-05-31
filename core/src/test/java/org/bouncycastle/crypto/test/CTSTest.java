package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.SkipjackEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * CTS tester
 */
public class CTSTest
    extends SimpleTest
{
    static byte[]   in1 = Hex.decode("4e6f7720697320746865207420");
    static byte[]   in2 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f0aaa");
    static byte[]   out1 = Hex.decode("9952f131588465033fa40e8a98");
    static byte[]   out2 = Hex.decode("358f84d01eb42988dc34efb994");
    static byte[]   out3 = Hex.decode("170171cfad3f04530c509b0c1f0be0aefbd45a8e3755a873bff5ea198504b71683c6");
    
    private void testCTS(
        int                 id,
        BlockCipher         cipher,
        CipherParameters    params,
        byte[]              input,
        byte[]              output)
        throws Exception
    {
        byte[]                  out = new byte[input.length];
        BufferedBlockCipher     engine = new CTSBlockCipher(cipher);

        engine.init(true, params);

        int len = engine.processBytes(input, 0, input.length, out, 0);

        engine.doFinal(out, len);

        if (!areEqual(output, out))
        {
            fail("failed encryption expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        engine.init(false, params);

        len = engine.processBytes(output, 0, output.length, out, 0);

        engine.doFinal(out, len);

        if (!areEqual(input, out))
        {
            fail("failed encryption expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
    }

    public String getName()
    {
        return "CTS";
    }

    public void performTest() 
        throws Exception
    {
        byte[]  key1 = { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF };
        byte[]  key2 = { (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0xee, (byte)0xff  };
        byte[]  iv = { 1, 2, 3, 4, 5, 6, 7, 8 };

        testCTS(1, new DESEngine(), new KeyParameter(key1), in1, out1);
        testCTS(2, new CBCBlockCipher(new DESEngine()), new ParametersWithIV(new KeyParameter(key1), iv), in1, out2);
        testCTS(3, new CBCBlockCipher(new SkipjackEngine()), new ParametersWithIV(new KeyParameter(key2), iv), in2, out3);
    }

    public static void main(
        String[]    args)
    {
        runTest(new CTSTest());
    }
}
