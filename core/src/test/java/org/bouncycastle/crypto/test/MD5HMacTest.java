
package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * MD5 HMac Test, test vectors from RFC 2202
 */
public class MD5HMacTest
    extends SimpleTest
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
        "9294727a3638bb1c13f48ef8158bfc9d",
        "750c783e6ab0b503eaa86e310a5db738",
        "56be34521d144c88dbb8c733f0e8b3f6",
        "697eaf0aca3a3aea3a75164746ffaa79",
        "56461ef2342edc00f9bab995690efd4c",
        "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
        "6f630fad67cda0ee1fb1f562db3aa53e"
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
        return "MD5HMac";
    }

    public void performTest()
    {
        HMac hmac = new HMac(new MD5Digest());
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

            if (!areEqual(resBuf, Hex.decode(digests[i])))
            {
                fail("Vector " + i + " failed");
            }
        }

        // test reset
        int vector = 0; // vector used for test
        byte[] m = messages[vector].getBytes();
        if (messages[vector].startsWith("0x"))
        {
            m = Hex.decode(messages[vector].substring(2));
        }
        hmac.init(new KeyParameter(Hex.decode(keys[vector])));
        hmac.update(m, 0, m.length);
        hmac.doFinal(resBuf, 0);
        hmac.reset();
        hmac.update(m, 0, m.length);
        hmac.doFinal(resBuf, 0);

        if (!areEqual(resBuf, Hex.decode(digests[vector])))
        {
            fail("Reset with vector " + vector + " failed");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new MD5HMacTest());
    }
}
