package org.bouncycastle.crypto.prng.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.X931SecureRandomBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HMAC SP800-90 DRBG
 */
public class X931Test
    extends SimpleTest
{
    public String getName()
    {
        return "X931";
    }

    public static void main(String[] args)
    {
        runTest(new X931Test());
    }

    private X931TestVector[] createTestVectorData()
    {
        return new X931TestVector[]
            {
                new X931TestVector(
                    new AESEngine(),
                    new AES128EntropyProvider(),
                    "f7d36762b9915f1ed585eb8e91700eb2",
                    "259e67249288597a4d61e7c0e690afae",
                    false,
                    new String[] {
                        "15f013af5a8e9df9a8e37500edaeac43",
                        "a9d74bb1c90a222adc398546d64879cf",
                        "0379e404042d58180764fb9e6c5d94bb",
                        "3c74603e036d28c79947ffb56fee4e51",
                        "e872101a4df81ebbe1e632fc87195d52",
                        "26a6b3d33b8e7e68b75d9630ec036314" }),
                new X931TestVector(
                    new DESedeEngine(),
                    new TDESEntropyProvider(),
                    "ef16ec643e5db5892cbc6eabba310b3410e6f8759e3e382c",
                    "55df103deaf68dc4",
                    false,
                    new String[] {
                        "9c960bb9662ce6de",
                        "d9d0e527fd0931da",
                        "3e2db9994e9e6995",
                        "0e3868aef8218cf7",
                        "7b0b0ca137f8fd81",
                        "f657df270ad12265" })
            };
    }

    public void performTest()
        throws Exception
    {
        X931TestVector[] vectors = createTestVectorData();

        for (int i = 0; i != vectors.length; i++)
        {
            X931TestVector tv = vectors[i];
            X931SecureRandomBuilder bld = new X931SecureRandomBuilder(tv.getEntropyProvider());

            bld.setDateTimeVector(Hex.decode(tv.getDateTimeVector()));

            SecureRandom rand = bld.build(tv.getEngine(), new KeyParameter(Hex.decode(tv.getKey())), tv.isPredictionResistant());

            for (int j = 0; j != tv.getExpected().length - 1; j++)
            {
                byte[] expected = Hex.decode(tv.getExpected()[j]);
                byte[] res = new byte[expected.length];

                rand.nextBytes(res);

                if (!Arrays.areEqual(expected, res))
                {
                    fail("expected output wrong [" + j + "] got : " + Strings.fromByteArray(Hex.encode(res)));
                }
            }

            byte[] expected = Hex.decode(tv.getExpected()[tv.getExpected().length - 1]);
            byte[] res = new byte[expected.length];

            for (int j = tv.getExpected().length - 1; j != 10000; j++)
            {
                rand.nextBytes(res);
            }

            if (!Arrays.areEqual(expected, res))
            {
                fail("expected output wrong [" + 10000 + "] got : " + Strings.fromByteArray(Hex.encode(res)));
            }
        }
    }

    private class AES128EntropyProvider
        extends TestEntropySourceProvider
    {
        AES128EntropyProvider()
        {
            super(Hex.decode(
                "35cc0ea481fc8a4f5f05c7d4667233b2"), true);
        }
    }

    private class TDESEntropyProvider
        extends TestEntropySourceProvider
    {
        TDESEntropyProvider()
        {
            super(Hex.decode(
                "96d872b9122c5e74"), true);
        }
    }
}
