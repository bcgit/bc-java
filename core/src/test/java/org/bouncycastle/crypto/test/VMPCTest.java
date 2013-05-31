package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.VMPCEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * VMPC Test
 */
public class VMPCTest extends SimpleTest
{
    private static final byte[] input = new byte[1000000];

    public String getName()
    {
        return "VMPC";
    }

    private void checkByte(byte[] array, int position, byte b)
    {
        if (array[position] != b)
        {
            fail("Fail on position " + position,
                new String(Hex.encode(new byte[] { b })),
                new String(Hex.encode(new byte[] { array[position] })));
        }
    }

    public void performTest()
    {
        byte[] key = Hex.decode("9661410AB797D8A9EB767C21172DF6C7");
        byte[] iv = Hex.decode("4B5C2F003E67F39557A8D26F3DA2B155");
        CipherParameters kp = new KeyParameter(key);
        CipherParameters kpwiv = new ParametersWithIV(kp, iv);

        VMPCEngine engine = new VMPCEngine();

        try
        {
            engine.init(true, kp);
            fail("init failed to throw expected exception");
        }
        catch (IllegalArgumentException e)
        {
            // Expected
        }

        engine.init(true, kpwiv);
        checkEngine(engine);

        engine.reset();
        byte[] output = checkEngine(engine);

        engine.init(false, kpwiv);
        byte[] recovered = new byte[output.length];
        engine.processBytes(output, 0, output.length, recovered, 0);

        if (!Arrays.areEqual(input, recovered))
        {
            fail("decrypted bytes differ from original bytes");
        }
    }

    private byte[] checkEngine(VMPCEngine engine)
    {
        byte[] output = new byte[input.length];
        engine.processBytes(input, 0, output.length, output, 0);

        checkByte(output, 0, (byte) 0xA8);
        checkByte(output, 1, (byte) 0x24);
        checkByte(output, 2, (byte) 0x79);
        checkByte(output, 3, (byte) 0xF5);
        checkByte(output, 252, (byte) 0xB8);
        checkByte(output, 253, (byte) 0xFC);
        checkByte(output, 254, (byte) 0x66);
        checkByte(output, 255, (byte) 0xA4);
        checkByte(output, 1020, (byte) 0xE0);
        checkByte(output, 1021, (byte) 0x56);
        checkByte(output, 1022, (byte) 0x40);
        checkByte(output, 1023, (byte) 0xA5);
        checkByte(output, 102396, (byte) 0x81);
        checkByte(output, 102397, (byte) 0xCA);
        checkByte(output, 102398, (byte) 0x49);
        checkByte(output, 102399, (byte) 0x9A);

        return output;
    }

    public static void main(String[] args)
    {
        runTest(new VMPCTest());
    }
}
