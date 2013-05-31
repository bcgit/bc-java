package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * GOST 28147 MAC tester 
 */
public class GOST28147MacTest
    implements Test
{
    //
    // these GOSTMac for testing.
    //
    static byte[]   gkeyBytes1 = Hex.decode("6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49");
    static byte[]   gkeyBytes2 = Hex.decode("6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49");

    static byte[]   input3 = Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
    static byte[]   input4 = Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f");

    static byte[]   output7 = Hex.decode("93468a46");
    static byte[]   output8 = Hex.decode("93468a46");

    public GOST28147MacTest()
    {
    }

    public TestResult perform()
    {
        // test1
        Mac          mac = new GOST28147Mac();
        KeyParameter key = new KeyParameter(gkeyBytes1);

        mac.init(key);

        mac.update(input3, 0, input3.length);

        byte[] out = new byte[4];

        mac.doFinal(out, 0);

        if (!Arrays.areEqual(out, output7))
        {
            return new SimpleTestResult(false, getName() + ": Failed test 1 - expected " + new String(Hex.encode(output7)) + " got " + new String(Hex.encode(out)));
        }

        // test2
        key = new KeyParameter(gkeyBytes2);

        ParametersWithSBox gparam = new ParametersWithSBox(key, GOST28147Engine.getSBox("E-A"));

        mac.init(gparam);

        mac.update(input4, 0, input4.length);

        out = new byte[4];

        mac.doFinal(out, 0);

        if (!Arrays.areEqual(out, output8))
        {
            return new SimpleTestResult(false, getName() + ": Failed test 2 - expected " + new String(Hex.encode(output8)) + " got " + new String(Hex.encode(out)));
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "GOST28147Mac";
    }

    public static void main(
        String[]    args)
    {
        GOST28147MacTest    test = new GOST28147MacTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
