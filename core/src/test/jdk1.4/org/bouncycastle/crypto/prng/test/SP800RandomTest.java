package org.bouncycastle.crypto.prng.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.prng.BasicEntropySourceProvider;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SP800RandomTest
    extends SimpleTest
{

    public String getName()
    {
        return "SP800RandomTest";
    }

    private void testHashRandom()
    {
        DRBGTestVector tv = new DRBGTestVector(
                            new SHA1Digest(),
                            new SHA1EntropyProvider().get(440),
                            true,
                            "2021222324",
                            80,
                            "HASH-DRBG-SHA1",
                            new String[]
                                {
                                    "532CA1165DCFF21C55592687639884AF4BC4B057DF8F41DE653AB44E2ADEC7C9303E75ABE277EDBF",
                                    "73C2C67C696D686D0C4DBCEB5C2AF7DDF6F020B6874FAE4390F102117ECAAFF54418529A367005A0"
                                })
                        .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");

        doHashTest(0, tv);

        tv =  new DRBGTestVector(
                            new SHA1Digest(),
                            new SHA1EntropyProvider().get(440),
                            false,
                            "2021222324",
                            80,
                            "HASH-DRBG-SHA1",
                            new String[]
                                {
                                    "AB438BD3B01A0AF85CFEE29F7D7B71621C4908B909124D430E7B406FB1086EA994C582E0D656D989",
                                    "29D9098F987E7005314A0F51B3DD2B8122F4AED706735DE6AD5DDBF223177C1E5F3AEBC52FAB90B9"
                                })
                            .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");

        doHashTest(1, tv);
    }

    private void doHashTest(int index, DRBGTestVector tv)
    {
        SP800SecureRandomBuilder rBuild = new SP800SecureRandomBuilder(new SHA1EntropyProvider());

        rBuild.setPersonalizationString(tv.personalizationString());
        rBuild.setSecurityStrength(tv.securityStrength());
        rBuild.setEntropyBitsRequired(tv.entropySource().getEntropy().length * 8);

        SecureRandom random = rBuild.buildHash(tv.getDigest(), tv.nonce(), tv.predictionResistance());

        byte[] expected = tv.expectedValue(0);
        byte[] produced = new byte[expected.length];

        random.nextBytes(produced);

        if (!Arrays.areEqual(expected, produced))
        {
            fail(index + " SP800 Hash SecureRandom produced incorrect result (1)");
        }

        random.nextBytes(produced);
        expected = tv.expectedValue(1);

        if (!Arrays.areEqual(expected, produced))
        {
            fail(index + " SP800 Hash SecureRandom produced incorrect result (2)");
        }

        //isTrue(random.getAlgorithm(), tv.getName().equals(random.getAlgorithm()));
    }

    private void testHMACRandom()
    {
        DRBGTestVector tv = new DRBGTestVector(
            new SHA1Digest(),
            new SHA1EntropyProvider().get(440),
            true,
            "2021222324",
            80,
            "HMAC-DRBG-SHA1",
            new String[]
                {
                    "6C37FDD729AA40F80BC6AB08CA7CC649794F6998B57081E4220F22C5C283E2C91B8E305AB869C625",
                    "CAF57DCFEA393B9236BF691FA456FEA7FDF1DF8361482CA54D5FA723F4C88B4FA504BF03277FA783"
                })
            .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");

        doHMACTest(tv);

        tv = new DRBGTestVector(
                new SHA1Digest(),
                new SHA1EntropyProvider().get(440),
                false,
                "2021222324",
                80,
                "HMAC-DRBG-SHA1",
                new String[]
                    {
                        "5A7D3B449F481CB38DF79AD2B1FCC01E57F8135E8C0B22CD0630BFB0127FB5408C8EFC17A929896E",
                        "82cf772ec3e84b00fc74f5df104efbfb2428554e9ce367d03aeade37827fa8e9cb6a08196115d948"
                    });

        doHMACTest(tv);
    }

    private void doHMACTest(DRBGTestVector tv)
    {
        SP800SecureRandomBuilder rBuild = new SP800SecureRandomBuilder(new SHA1EntropyProvider());

        rBuild.setPersonalizationString(tv.personalizationString());
        rBuild.setSecurityStrength(tv.securityStrength());
        rBuild.setEntropyBitsRequired(tv.entropySource().getEntropy().length * 8);

        SecureRandom random = rBuild.buildHMAC(new HMac(tv.getDigest()), tv.nonce(), tv.predictionResistance());

        byte[] expected = tv.expectedValue(0);
        byte[] produced = new byte[expected.length];

        random.nextBytes(produced);
        if (!Arrays.areEqual(expected, produced))
        {
            fail("SP800 HMAC SecureRandom produced incorrect result (1)");
        }

        random.nextBytes(produced);
        expected = tv.expectedValue(1);

        if (!Arrays.areEqual(expected, produced))
        {
            fail("SP800 HMAC SecureRandom produced incorrect result (2)");
        }

        //isTrue(random.getAlgorithm(), tv.getName().equals(random.getAlgorithm()));
    }

    private void testCTRRandom()
    {
        DRBGTestVector tv = new DRBGTestVector(
                                    new DESedeEngine(), 168,
                                    new Bit232EntropyProvider().get(232),
                                    false,
                                    "20212223242526",
                                    112,
                                    "CTR-DRBG-3KEY-TDES",
                                    new String[]
                                        {
                                            "ABC88224514D0316EA3D48AEE3C9A2B4",
                                            "D3D3F372E43E7ABDC4FA293743EED076"
                                        }
                                );

        doCTRTest(tv);

        tv = new DRBGTestVector(
                    new DESedeEngine(), 168,
                    new Bit232EntropyProvider().get(232),
                    true,
                    "20212223242526",
                    112,
                    "CTR-DRBG-3KEY-TDES",
                    new String[]
                        {
                            "64983055D014550B39DE699E43130B64",
                            "035FDDA8582A2214EC722C410A8D95D3"
                        }
                )
        .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C");

        doCTRTest(tv);
    }

    private void doCTRTest(DRBGTestVector tv)
    {
        SP800SecureRandomBuilder rBuild = new SP800SecureRandomBuilder(new Bit232EntropyProvider());

        rBuild.setPersonalizationString(tv.personalizationString());
        rBuild.setSecurityStrength(tv.securityStrength());
        rBuild.setEntropyBitsRequired(tv.entropySource().getEntropy().length * 8);

        SecureRandom random = rBuild.buildCTR(tv.getCipher(), tv.keySizeInBits(), tv.nonce(), tv.predictionResistance());

        byte[] expected = tv.expectedValue(0);
        byte[] produced = new byte[expected.length];

        random.nextBytes(produced);
        if (!Arrays.areEqual(expected, produced))
        {
            fail("SP800 CTR SecureRandom produced incorrect result (1)");
        }

        random.nextBytes(produced);
        expected = tv.expectedValue(1);

        if (!Arrays.areEqual(expected, produced))
        {
            fail("SP800 CTR SecureRandom produced incorrect result (2)");
        }

        //isTrue(random.getAlgorithm(), tv.getName().equals(random.getAlgorithm()));
    }

    private void testGenerateSeed()
    {
        SP800SecureRandomBuilder rBuild = new SP800SecureRandomBuilder(new Bit232EntropyProvider());

        rBuild.setPersonalizationString(Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"));
        rBuild.setSecurityStrength(112);
        rBuild.setEntropyBitsRequired(232);

        SecureRandom random = rBuild.buildCTR(new DESedeEngine(), 168, Hex.decode("20212223242526"), false);

        rBuild = new SP800SecureRandomBuilder(new BasicEntropySourceProvider(random, false));

        rBuild.setPersonalizationString(Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"));
        rBuild.setSecurityStrength(112);
        rBuild.setEntropyBitsRequired(232);

        random = rBuild.buildCTR(new DESedeEngine(), 168, Hex.decode("20212223242526"), false);

        byte[] expected = Hex.decode("760bed7d92b083b10af31cf0656081eb51d241f0");

        byte[] produced = random.generateSeed(20);

        if (!Arrays.areEqual(expected, produced))
        {
            fail("SP800 CTR SecureRandom.generateSeed() produced incorrect result (1)");
        }
    }

/*
    private void testNames()
    {
        SP800SecureRandomBuilder rBuild = new SP800SecureRandomBuilder(new Bit232EntropyProvider());

        rBuild.setPersonalizationString(Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"));
        rBuild.setSecurityStrength(112);
        rBuild.setEntropyBitsRequired(232);

        isEquals("CTR-DRBG-3KEY-TDES", rBuild.buildCTR(new DESedeEngine(), 168, Hex.decode("20212223242526"), false).getAlgorithm());

        isEquals("CTR-DRBG-AES128", rBuild.buildCTR(new AESEngine(), 128, Hex.decode("20212223242526"), false).getAlgorithm());
        isEquals("CTR-DRBG-AES192", rBuild.buildCTR(new AESEngine(), 192, Hex.decode("20212223242526"), false).getAlgorithm());
        isEquals("CTR-DRBG-AES256", rBuild.buildCTR(new AESEngine(), 256, Hex.decode("20212223242526"), false).getAlgorithm());

        isEquals("HASH-DRBG-SHA256", rBuild.buildHash(new SHA256Digest(), Hex.decode("20212223242526"), false).getAlgorithm());
        isEquals("HASH-DRBG-SHA384", rBuild.buildHash(new SHA384Digest(), Hex.decode("20212223242526"), false).getAlgorithm());
        isEquals("HASH-DRBG-SHA512", rBuild.buildHash(new SHA512Digest(), Hex.decode("20212223242526"), false).getAlgorithm());

        isEquals("HMAC-DRBG-SHA256", rBuild.buildHMAC(new HMac(new SHA256Digest()), Hex.decode("20212223242526"), false).getAlgorithm());
        isEquals("HMAC-DRBG-SHA384", rBuild.buildHMAC(new HMac(new SHA384Digest()), Hex.decode("20212223242526"), false).getAlgorithm());
        isEquals("HMAC-DRBG-SHA512", rBuild.buildHMAC(new HMac(new SHA512Digest()), Hex.decode("20212223242526"), false).getAlgorithm());
    }
*/

    public void performTest()
        throws Exception
    {
        testHashRandom();
        testHMACRandom();
        testCTRRandom();
        testGenerateSeed();
 //       testNames();
    }

    public static void main(String[] args)
    {
        runTest(new SP800RandomTest());
    }

    // for HMAC/Hash
    private class SHA1EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA1EntropyProvider()
        {
            super(
                Hex.decode(
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536"
                        + "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6"
                        + "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6"), true);
        }
    }

    // for Dual EC
    private class SHA256EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA256EntropyProvider()
        {
            super(Hex.decode(
                "000102030405060708090A0B0C0D0E0F " +
                    "808182838485868788898A8B8C8D8E8F" +
                    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"), true);
        }
    }

    private class Bit232EntropyProvider
        extends TestEntropySourceProvider
    {
        Bit232EntropyProvider()
        {
            super(Hex.decode(
               "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C" +
               "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C" +
               "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDC"), true);
        }
    }
}
