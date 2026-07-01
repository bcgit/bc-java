package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * SM3 HMac Test, using the standard RFC 2202 / RFC 4231 key/message inputs. SM3 is a 256-bit
 * digest, so HMAC-SM3 produces a full 32-byte output; these vectors guard against the output
 * length being truncated.
 */
public class SM3HMacTest
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
        "12d66c84b4a40ad8035c263e419bd43c7e52fb438b930eba0c94e34cdb9b63f3",
        "2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882",
        "7bfeba1b1518329f73aad171e89009fc41d43b66de11e779b5615bfbf0b85973",
        "b57c79be03472aeb8cada581dea332cb2ba83d19cb1b052dd07194def75fb8cd",
        "47541fc981b3457ab94e71b31911c73762ef466f5fe84411467f90686d97120a",
        "c794651f5455f80546855f744ff50146d5286e1cb677d5088c059cd8b03bb9ce",
        "0888924905d64874be20dc784b57f2cf9ea375905339075c5af90418b4bf8705"
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
        return "SM3HMac";
    }

    public TestResult perform()
    {
        HMac hmac = new HMac(new SM3Digest());
        byte[] resBuf = new byte[hmac.getMacSize()];

        if (hmac.getMacSize() != 32)
        {
            return new SimpleTestResult(false, getName() + ": expected 32 byte MAC but got " + hmac.getMacSize());
        }

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
                return new SimpleTestResult(false, getName() + ": Vector " + i + " failed got " + new String(Hex.encode(resBuf)));
            }
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        SM3HMacTest   test = new SM3HMacTest();
        TestResult          result = test.perform();

        System.out.println(result);
    }
}
