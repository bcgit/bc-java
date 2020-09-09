package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class RSATest
    extends SimpleTest
{
    /*
     * Based on https://github.com/crocs-muni/roca/blob/master/java/BrokenKey.java
     * Credits: ported to Java by Martin Paljak
     */
    static class BrokenKey_CVE_2017_15361
    {
        private static final int[] prims = new int[]{ 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
            67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167 };
        private static final BigInteger[] primes = new BigInteger[prims.length];

        static
        {
            for (int i = 0; i < prims.length; i++)
            {
                primes[i] = BigInteger.valueOf(prims[i]);
            }
        }

        private static final BigInteger[] markers = new BigInteger[]
        {
            new BigInteger("6"),
            new BigInteger("30"),
            new BigInteger("126"),
            new BigInteger("1026"),
            new BigInteger("5658"),
            new BigInteger("107286"),
            new BigInteger("199410"),
            new BigInteger("8388606"),
            new BigInteger("536870910"),
            new BigInteger("2147483646"),
            new BigInteger("67109890"),
            new BigInteger("2199023255550"),
            new BigInteger("8796093022206"),
            new BigInteger("140737488355326"),
            new BigInteger("5310023542746834"),
            new BigInteger("576460752303423486"),
            new BigInteger("1455791217086302986"),
            new BigInteger("147573952589676412926"),
            new BigInteger("20052041432995567486"),
            new BigInteger("6041388139249378920330"),
            new BigInteger("207530445072488465666"),
            new BigInteger("9671406556917033397649406"),
            new BigInteger("618970019642690137449562110"),
            new BigInteger("79228162521181866724264247298"),
            new BigInteger("2535301200456458802993406410750"),
            new BigInteger("1760368345969468176824550810518"),
            new BigInteger("50079290986288516948354744811034"),
            new BigInteger("473022961816146413042658758988474"),
            new BigInteger("10384593717069655257060992658440190"),
            new BigInteger("144390480366845522447407333004847678774"),
            new BigInteger("2722258935367507707706996859454145691646"),
            new BigInteger("174224571863520493293247799005065324265470"),
            new BigInteger("696898287454081973172991196020261297061886"),
            new BigInteger("713623846352979940529142984724747568191373310"),
            new BigInteger("1800793591454480341970779146165214289059119882"),
            new BigInteger("126304807362733370595828809000324029340048915994"),
            new BigInteger("11692013098647223345629478661730264157247460343806"),
            new BigInteger("187072209578355573530071658587684226515959365500926")
        };

        public static boolean isAffected(RSAKeyParameters publicKey)
        {
            BigInteger modulus = publicKey.getModulus();

            for (int i = 0; i < primes.length; i++)
            {
                int remainder = modulus.remainder(primes[i]).intValue();
                if (!markers[i].testBit(remainder))
                {
                    return false;
                }
            }

            return true;
        }
    }

    static BigInteger mod = new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16);
    static BigInteger pubExp = new BigInteger("11", 16);
    static BigInteger privExp = new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16);
    static BigInteger p = new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16);
    static BigInteger q = new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16);
    static BigInteger pExp = new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16);
    static BigInteger qExp = new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16);
    static BigInteger crtCoef = new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16);

    static String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    //
    // to check that we handling byte extension by big number correctly.
    //
    static String edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    static byte[] oversizedSig = Hex.decode("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
    static byte[] dudBlock = Hex.decode("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
    static byte[] truncatedDataBlock = Hex.decode("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
    static byte[] incorrectPadding = Hex.decode("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
    static byte[] missingDataBlock = Hex.decode("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    public String getName()
    {
        return "RSA";
    }

    private void testStrictPKCS1Length(RSAKeyParameters pubParameters, RSAKeyParameters privParameters)
    {
        AsymmetricBlockCipher eng = new RSAEngine();

        eng.init(true, privParameters);

        byte[] data = null;
        byte[] overSized = null;

        try
        {
            overSized = data = eng.processBlock(oversizedSig, 0, oversizedSig.length);
        }
        catch (Exception e)
        {
            fail("RSA: failed - exception " + e.toString(), e);
        }

        eng = new PKCS1Encoding(eng);

        eng.init(false, pubParameters);

        try
        {
            data = eng.processBlock(overSized, 0, overSized.length);

            fail("oversized signature block not recognised");
        }
        catch (InvalidCipherTextException e)
        {
            if (!e.getMessage().equals("block incorrect size"))
            {
                fail("RSA: failed - exception " + e.toString(), e);
            }
        }

        eng = new PKCS1Encoding(new RSAEngine(), Hex.decode("feedbeeffeedbeeffeedbeef"));
        eng.init(false, new ParametersWithRandom(privParameters, new SecureRandom()));

        try
        {
            data = eng.processBlock(overSized, 0, overSized.length);
            isTrue("not fallback", Arrays.areEqual(Hex.decode("feedbeeffeedbeeffeedbeef"), data));
        }
        catch (InvalidCipherTextException e)
        {
            fail("RSA: failed - exception " + e.toString(), e);
        }

        //System.setProperty(PKCS1Encoding.STRICT_LENGTH_ENABLED_PROPERTY, "false");

        System.getProperties().put(PKCS1Encoding.NOT_STRICT_LENGTH_ENABLED_PROPERTY, "true");
        eng = new PKCS1Encoding(new RSAEngine());

        eng.init(false, pubParameters);

        try
        {
            data = eng.processBlock(overSized, 0, overSized.length);
        }
        catch (InvalidCipherTextException e)
        {
            fail("RSA: failed - exception " + e.toString(), e);
        }

        System.getProperties().remove(PKCS1Encoding.NOT_STRICT_LENGTH_ENABLED_PROPERTY);
    }

    private void testUnsafeModulusAndWrongExp()
    {
        try
        {
            try
            {
                new RSAKeyParameters(false, mod, pubExp.multiply(BigInteger.valueOf(2)));

                fail("no exception");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("RSA publicExponent is even".equals(e.getMessage()));
            }

            try
            {
                new RSAKeyParameters(false, mod.multiply(BigInteger.valueOf(2)), pubExp);

                fail("no exception");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("RSA modulus is even".equals(e.getMessage()));
            }

            try
            {
                new RSAKeyParameters(false, mod.multiply(BigInteger.valueOf(3)), pubExp);

                fail("no exception");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("RSA modulus has a small prime factor".equals(e.getMessage()));
            }

            System.getProperties().put("org.bouncycastle.rsa.allow_unsafe_mod", "true");

            // this should now work (sigh...)
            new RSAKeyParameters(false, mod.multiply(BigInteger.valueOf(3)), pubExp);
        }
        finally
        {
            System.getProperties().remove("org.bouncycastle.rsa.allow_unsafe_mod");
        }
    }

    private void testTruncatedPKCS1Block(RSAKeyParameters pubParameters, RSAKeyParameters privParameters)
    {
        checkForPKCS1Exception(pubParameters, privParameters, truncatedDataBlock, "block incorrect");
    }

    private void testDudPKCS1Block(RSAKeyParameters pubParameters, RSAKeyParameters privParameters)
    {
        checkForPKCS1Exception(pubParameters, privParameters, dudBlock, "block incorrect");
    }

    private void testWrongPaddingPKCS1Block(RSAKeyParameters pubParameters, RSAKeyParameters privParameters)
    {
        checkForPKCS1Exception(pubParameters, privParameters, incorrectPadding, "block incorrect");
    }

    private void testMissingDataPKCS1Block(RSAKeyParameters pubParameters, RSAKeyParameters privParameters)
    {
        checkForPKCS1Exception(pubParameters, privParameters, missingDataBlock, "block incorrect");
    }

    private void checkForPKCS1Exception(RSAKeyParameters pubParameters, RSAKeyParameters privParameters, byte[] inputData, String expectedMessage)
    {
        AsymmetricBlockCipher eng = new RSAEngine();

        eng.init(true, privParameters);

        byte[] data = null;

        try
        {
            data = eng.processBlock(inputData, 0, inputData.length);
        }
        catch (Exception e)
        {
            fail("RSA: failed - exception " + e.toString(), e);
        }

        eng = new PKCS1Encoding(eng);

        eng.init(false, pubParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);

            fail("incorrect block not recognised");
        }
        catch (InvalidCipherTextException e)
        {
            if (!e.getMessage().equals(expectedMessage))
            {
                fail("RSA: failed - exception " + e.toString(), e);
            }
        }
    }

    private void testOAEP(RSAKeyParameters pubParameters, RSAKeyParameters privParameters)
    {
        //
        // OAEP - public encrypt, private decrypt
        //
        AsymmetricBlockCipher eng = new OAEPEncoding(new RSAEngine());
        byte[] data = Hex.decode(input);

        eng.init(true, pubParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, privParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(new String(Hex.encode(data))))
        {
            fail("failed OAEP Test");
        }

        // check for oversized input
        byte[] message = new byte[87];
        RSAEngine rsaEngine = new RSAEngine();
        AsymmetricBlockCipher cipher = new OAEPEncoding(rsaEngine, new SHA1Digest(), new SHA1Digest(), message);
        cipher.init(true, new ParametersWithRandom(pubParameters, new SecureRandom()));

        try
        {
            cipher.processBlock(message, 0, message.length);

            fail("no exception thrown");
        }
        catch (DataLengthException e)
        {
            isTrue("message mismatch", "input data too long".equals(e.getMessage()));
        }
        catch (InvalidCipherTextException e)
        {
            fail("failed - exception " + e.toString(), e);
        }

    }

    private void zeroBlockTest(CipherParameters encParameters, CipherParameters decParameters)
    {
        AsymmetricBlockCipher eng = new PKCS1Encoding(new RSAEngine());

        eng.init(true, encParameters);

        if (eng.getOutputBlockSize() != ((PKCS1Encoding)eng).getUnderlyingCipher().getOutputBlockSize())
        {
            fail("PKCS1 output block size incorrect");
        }

        byte[] zero = new byte[0];
        byte[] data = null;

        try
        {
            data = eng.processBlock(zero, 0, zero.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, decParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!Arrays.areEqual(zero, data))
        {
            fail("failed PKCS1 zero Test");
        }
    }

    private void test_CVE_2017_15361()
    {
        SecureRandom random = new SecureRandom();
        RSAKeyPairGenerator pGen = new RSAKeyPairGenerator();
        BigInteger e = BigInteger.valueOf(0x11);

        for (int strength = 512; strength <= 2048; strength += 32)
        {
            pGen.init(new RSAKeyGenerationParameters(
                e, random, strength, 100));

            RSAKeyParameters pubKey = (RSAKeyParameters)pGen.generateKeyPair().getPublic();

            if (BrokenKey_CVE_2017_15361.isAffected(pubKey))
            {
                fail("failed CVE-2017-15361 vulnerability test for generated RSA key");
            }
        }
    }

    public void performTest()
    {
        RSAKeyParameters pubParameters = new RSAKeyParameters(false, mod, pubExp);
        RSAKeyParameters privParameters = new RSAPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
        byte[] data = Hex.decode(edgeInput);

        //
        // RAW
        //
        AsymmetricBlockCipher eng = new RSAEngine();

        eng.init(true, pubParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("RSA: failed - exception " + e.toString(), e);
        }

        eng.init(false, privParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!edgeInput.equals(new String(Hex.encode(data))))
        {
            fail("failed RAW edge Test");
        }

        data = Hex.decode(input);

        eng.init(true, pubParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, privParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(new String(Hex.encode(data))))
        {
            fail("failed RAW Test");
        }

        //
        // PKCS1 - public encrypt, private decrypt
        //
        eng = new PKCS1Encoding(eng);

        eng.init(true, pubParameters);

        if (eng.getOutputBlockSize() != ((PKCS1Encoding)eng).getUnderlyingCipher().getOutputBlockSize())
        {
            fail("PKCS1 output block size incorrect");
        }

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, privParameters);

        byte[] plainData = null;
        try
        {
            plainData = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(Hex.toHexString(plainData)))
        {
            fail("failed PKCS1 public/private Test");
        }

        PKCS1Encoding fEng = new PKCS1Encoding(new RSAEngine(), input.length() / 2);
        fEng.init(false, new ParametersWithRandom(privParameters, new SecureRandom()));
        try
        {
            plainData = fEng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(Hex.toHexString(plainData)))
        {
            fail("failed PKCS1 public/private fixed Test");
        }

        fEng = new PKCS1Encoding(new RSAEngine(), input.length());
        fEng.init(false, new ParametersWithRandom(privParameters, new SecureRandom()));
        try
        {
            data = fEng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (input.equals(Hex.toHexString(data)))
        {
            fail("failed to recognise incorrect plaint text length");
        }

        data = plainData;

        //
        // PKCS1 - private encrypt, public decrypt
        //
        eng = new PKCS1Encoding(((PKCS1Encoding)eng).getUnderlyingCipher());

        eng.init(true, privParameters);

        try
        {
            data = eng.processBlock(plainData, 0, plainData.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, pubParameters);

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(Hex.toHexString(data)))
        {
            fail("failed PKCS1 private/public Test");
        }

        zeroBlockTest(pubParameters, privParameters);
        zeroBlockTest(privParameters, pubParameters);

        //
        // key generation test
        //
        RSAKeyPairGenerator pGen = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters genParam = new RSAKeyGenerationParameters(
            BigInteger.valueOf(0x11), new SecureRandom(), 768, 25);

        pGen.init(genParam);

        AsymmetricCipherKeyPair pair = pGen.generateKeyPair();

        eng = new RSAEngine();

        if (((RSAKeyParameters)pair.getPublic()).getModulus().bitLength() < 768)
        {
            fail("failed key generation (768) length test");
        }

        eng.init(true, pair.getPublic());

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, pair.getPrivate());

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(new String(Hex.encode(data))))
        {
            fail("failed key generation (768) Test");
        }

        genParam = new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 1024, 25);

        pGen.init(genParam);
        pair = pGen.generateKeyPair();

        eng.init(true, pair.getPublic());

        if (((RSAKeyParameters)pair.getPublic()).getModulus().bitLength() < 1024)
        {
            fail("failed key generation (1024) length test");
        }

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        eng.init(false, pair.getPrivate());

        try
        {
            data = eng.processBlock(data, 0, data.length);
        }
        catch (Exception e)
        {
            fail("failed - exception " + e.toString(), e);
        }

        if (!input.equals(new String(Hex.encode(data))))
        {
            fail("failed key generation (1024) test");
        }

        genParam = new RSAKeyGenerationParameters(
            BigInteger.valueOf(0x11), new SecureRandom(), 128, 25);
        pGen.init(genParam);

        for (int i = 0; i < 100; ++i)
        {
            pair = pGen.generateKeyPair();
            RSAPrivateCrtKeyParameters privKey = (RSAPrivateCrtKeyParameters)pair.getPrivate();
            BigInteger pqDiff = privKey.getP().subtract(privKey.getQ()).abs();

            if (pqDiff.bitLength() < 42)
            {
                fail("P and Q too close in RSA key pair");
            }
        }

        testOAEP(pubParameters, privParameters);
        testStrictPKCS1Length(pubParameters, privParameters);
        testDudPKCS1Block(pubParameters, privParameters);
        testMissingDataPKCS1Block(pubParameters, privParameters);
        testTruncatedPKCS1Block(pubParameters, privParameters);
        testWrongPaddingPKCS1Block(pubParameters, privParameters);
        test_CVE_2017_15361();
        testUnsafeModulusAndWrongExp();

        try
        {
            new RSAEngine().processBlock(new byte[]{1}, 0, 1);
            fail("failed initialisation check");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }


    public static void main(
        String[] args)
    {
        runTest(new RSATest());
    }
}
