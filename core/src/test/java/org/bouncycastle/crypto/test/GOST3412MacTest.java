package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * see GOST_R_3413-2015
 */
public class GOST3412MacTest
    implements Test
{

    public String getName()
    {
        return "GOST 3412 2015 MAC test";
    }

    public TestResult perform()
    {


        byte[][] inputs = new byte[][]{
            Hex.decode("1122334455667700ffeeddccbbaa9988"),
            Hex.decode("00112233445566778899aabbcceeff0a"),
            Hex.decode("112233445566778899aabbcceeff0a00"),
            Hex.decode("2233445566778899aabbcceeff0a0011"),
        };
        Mac mac = new CMac(new GOST3412_2015Engine(), 64);

        byte[] output = Hex.decode("336f4d296059fbe3");

        KeyParameter key =
            new KeyParameter(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"));
        mac.init(key);

        for (int i = 0; i != inputs.length; i++)
        {
            mac.update(inputs[i], 0, inputs[i].length);
        }

        byte[] out = new byte[8];

        mac.doFinal(out, 0);

        if (!Arrays.areEqual(out, output))
        {
            return new SimpleTestResult(false, getName() + ": Failed test 1 - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        return new SimpleTestResult(true, getName() + ": Okay");

    }


    public static void main(String[] args)
    {
        GOST3412MacTest test = new GOST3412MacTest();
        TestResult result = test.perform();

        System.out.println(result);
    }


}
