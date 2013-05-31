package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SipHashTest
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] input = Hex.decode("000102030405060708090a0b0c0d0e");

        byte[] expected = Hex.decode("e545be4961ca29a1");

        Mac mac = Mac.getInstance("SipHash", "BC");

        mac.init(new SecretKeySpec(key, "SipHash"));

        mac.update(input, 0, input.length);

        byte[] result = mac.doFinal();

        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for doFinal()");
        }

        mac.init(new SecretKeySpec(key, "SipHash-2-4"));

        mac.update(input, 0, input.length);

        result = mac.doFinal();
        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for second doFinal()");
        }

        mac = Mac.getInstance("SipHash-2-4", "BC");

        mac.init(new SecretKeySpec(key, "SipHash-2-4"));

        mac.update(input, 0, input.length);

        result = mac.doFinal();
        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for alias");
        }

        // SipHash 4-8
        expected = Hex.decode("e0a6a97dd589d383");

        mac = Mac.getInstance("SipHash-4-8", "BC");

        mac.init(new SecretKeySpec(key, "SipHash"));

        mac.update(input, 0, input.length);

        result = mac.doFinal();

        if (!Arrays.areEqual(expected, result))
        {
            fail("Result does not match expected value for SipHash 4-8");
        }
    }

    public String getName()
    {
        return "SipHash";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SipHashTest());
    }
}
