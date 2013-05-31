package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * RIPEMD160 HMac Test, test vectors from RFC 2286
 */
public class RIPEMD160HMacTest
    implements Test
{
    final static String[] keys = {
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4a656665",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    };

    final static String[] digests = {
        "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
        "dda6c0213a485a9e24f4742064a7f033b43c4069",
        "b0b105360de759960ab4f35298e116e295d8e7c1",
        "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
        "7619693978f91d90539ae786500ff3d8e0518e39",
        "6466ca07ac5eac29e1bd523e5ada7605b791fd8b",
        "69ea60798d71616cce5fd0871e23754cd75d5a0a"
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
        return "RIPEMD160HMac";
    }

    public TestResult perform()
    {
        HMac hmac = new HMac(new RIPEMD160Digest());
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
        RIPEMD160HMacTest   test = new RIPEMD160HMacTest();
        TestResult          result = test.perform();

        System.out.println(result);
    }
}
