package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * RIPEMD128 HMac Test, test vectors from RFC 2286
 */
public class RIPEMD128HMacTest
    implements Test
{
    final static String[] keys = {
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4a656665",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    };

    final static String[] digests = {
        "fbf61f9492aa4bbf81c172e84e0734db",
        "875f828862b6b334b427c55f9f7ff09b",
        "09f0b2846d2f543da363cbec8d62a38d",
        "bdbbd7cf03e44b5aa60af815be4d2294",
        "e79808f24b25fd031c155f0d551d9a3a",
        "dc732928de98104a1f59d373c150acbb",
        "5c6bec96793e16d40690c237635f30c5"
    };

    final static String[] messages = {
        "Hi There",
        "what do ya want for nothing?",
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "Test With Truncation",
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    };
        
    public String getName()
    {
        return "RIPEMD128HMac";
    }

    public TestResult perform()
    {
        HMac hmac = new HMac(new RIPEMD128Digest());
        byte[] resBuf = new byte[hmac.getMacSize()];

        for (int i = 0; i < messages.length; i++)
        {
            byte[] m = messages[i].getBytes();
            if (messages[i].startsWith("0x"))
            {
                m = Hex.decode(messages[i].substring(2));
            }
            hmac.init(new KeyParameter(Hex.decode(keys[i])));
            hmac.update(m, 0, m.length);
            hmac.doFinal(resBuf, 0);

            if (!Arrays.areEqual(resBuf, Hex.decode(digests[i])))
            {
                return new SimpleTestResult(false, getName() + ": Vector " + i + " failed");
            }
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        RIPEMD128HMacTest   test = new RIPEMD128HMacTest();
        TestResult          result = test.perform();

        System.out.println(result);
    }
}
