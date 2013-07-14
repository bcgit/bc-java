package org.bouncycastle.jce.provider.test;

import java.security.MessageDigest;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class DigestTest
    extends SimpleTest
{
    final static String provider = "BC";

    static private String[][] abcVectors =
    {
        { "MD2", "da853b0d3f88d99b30283a69e6ded6bb" },
        { "MD4", "a448017aaf21d8525fc10ae87aa6729d" },
        { "MD5", "900150983cd24fb0d6963f7d28e17f72"},
        { "SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "SHA-224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        { "SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "SHA-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
        { "SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { "SHA-512/224", "4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA" },
        { "SHA-512/256", "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23" },
        { "RIPEMD128", "c14a12199c66e4ba84636b0f69144c77" },
        { "RIPEMD160", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
        { "RIPEMD256", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65" },
        { "RIPEMD320", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d" },
        { "Tiger", "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93" },
        { "GOST3411", "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c" },
        { "WHIRLPOOL", "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5" },
        { "SM3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" },
    };
    
    public String getName()
    {
        return "Digest";
    }

    void test(String algorithm)
        throws Exception
    {
        byte[] message = "hello world".getBytes();

        MessageDigest digest = MessageDigest.getInstance(algorithm, provider);

        byte[] result = digest.digest(message);
        byte[] result2 = digest.digest(message);

        // test one digest the same message with the same instance
        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 1 not equal");
        }

        // test two, single byte updates
        for (int i = 0; i < message.length; i++)
        {
            digest.update(message[i]);
        }
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 2 not equal");
        }

        // test three, two half updates
        digest.update(message, 0, message.length/2);
        digest.update(message, message.length/2, message.length-message.length/2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 3 not equal");
        }

        // test four, clone test
        digest.update(message, 0, message.length/2);
        MessageDigest d = (MessageDigest)digest.clone();
        digest.update(message, message.length/2, message.length-message.length/2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 4(a) not equal");
        }

        d.update(message, message.length/2, message.length-message.length/2);
        result2 = d.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 4(b) not equal");
        }

        // test five, check reset() method
        digest.update(message, 0, message.length/2);
        digest.reset();
        digest.update(message, 0, message.length/2);
        digest.update(message, message.length/2, message.length-message.length/2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 5 not equal");
        }
    }

    /**
     * Test the hash against a standard value for the string "abc"
     * 
     * @param algorithm algorithm to test
     * @param hash expected value
     * @return the test result.
     */
    void abcTest(
        String algorithm,
        String hash)
        throws Exception
    {
        byte[] abc = { (byte)0x61, (byte)0x62, (byte)0x63 };
        
        MessageDigest digest = MessageDigest.getInstance(algorithm, provider);

        byte[] result = digest.digest(abc);
        
        if (!MessageDigest.isEqual(result, Hex.decode(hash)))
        {
            fail("abc result not equal for " + algorithm);
        }
    }
    
    public void performTest()
        throws Exception
    {
        for (int i = 0; i != abcVectors.length; i++)
        {
            test(abcVectors[i][0]);
         
            abcTest(abcVectors[i][0], abcVectors[i][1]);
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DigestTest());
    }
}

