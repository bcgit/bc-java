package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.DESedeWrapEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.security.SecureRandom;

/**
 * DESede tester
 */
public class DESedeTest
    extends CipherTest
{
    static private byte[] weakKey =     // first 8 bytes non-weak
         {
             (byte)0x06,(byte)0x01,(byte)0x01,(byte)0x01, (byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01,
             (byte)0x1f,(byte)0x1f,(byte)0x1f,(byte)0x1f, (byte)0x0e,(byte)0x0e,(byte)0x0e,(byte)0x0e,
             (byte)0xe0,(byte)0xe0,(byte)0xe0,(byte)0xe0, (byte)0xf1,(byte)0xf1,(byte)0xf1,(byte)0xf1,
         };

    static String   input1 = "4e6f77206973207468652074696d6520666f7220616c6c20";
    static String   input2 = "4e6f7720697320746865";

    static SimpleTest[]  tests =
            {
                new BlockCipherVectorTest(0, new DESedeEngine(),
                        new DESedeParameters(Hex.decode("0123456789abcdef0123456789abcdef")),
                        input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
                new BlockCipherVectorTest(1, new DESedeEngine(),
                        new DESedeParameters(Hex.decode("0123456789abcdeffedcba9876543210")),
                        input1, "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c"),
                new BlockCipherVectorTest(2, new DESedeEngine(),
                        new DESedeParameters(Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef")),
                        input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
                new BlockCipherVectorTest(3, new DESedeEngine(),
                        new DESedeParameters(Hex.decode("0123456789abcdeffedcba98765432100123456789abcdef")),
                        input1, "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c")
            };

    DESedeTest()
    {
        super(tests, new DESedeEngine(), new KeyParameter(new byte[16]));
    }

    private void wrapTest(
        int     id,
        byte[]  kek,
        byte[]  iv,
        byte[]  in,
        byte[]  out)
    {
        Wrapper wrapper = new DESedeWrapEngine();

        wrapper.init(true, new ParametersWithIV(new KeyParameter(kek), iv));

        try
        {
            byte[]  cText = wrapper.wrap(in, 0, in.length);
            if (!areEqual(cText, out))
            {
                fail(": failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
            }
        }
        catch (Exception e)
        {
            fail("failed wrap test exception: " + e.toString(), e);
        }

        wrapper.init(false, new KeyParameter(kek));

        try
        {
            byte[]  pText = wrapper.unwrap(out, 0, out.length);
            if (!areEqual(pText, in))
            {
                fail("failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText)));
            }
        }
        catch (Exception e)
        {
            fail("failed unwrap test exception: " + e.toString(), e);
        }
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        byte[]  kek1 = Hex.decode("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f");
        byte[]  iv1 = Hex.decode("5dd4cbfc96f5453b");
        byte[]  in1 = Hex.decode("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98");
        byte[]  out1 = Hex.decode("690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4");
        
        wrapTest(1, kek1, iv1, in1, out1);

        //
        // key generation
        //
        SecureRandom       random = new SecureRandom();
        DESedeKeyGenerator keyGen = new DESedeKeyGenerator();
        
        keyGen.init(new KeyGenerationParameters(random, 112));
        
        byte[] kB = keyGen.generateKey();
        
        if (kB.length != 16)
        {
            fail("112 bit key wrong length.");
        }
        
        keyGen.init(new KeyGenerationParameters(random, 168));
        
        kB = keyGen.generateKey();
        
        if (kB.length != 24)
        {
            fail("168 bit key wrong length.");
        }
        
        try
        {
            keyGen.init(new KeyGenerationParameters(random, 200));
            
            fail("invalid key length not detected.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            DESedeParameters.isWeakKey(new byte[4], 0);
            fail("no exception on small key");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("key material too short."))
            {
                fail("wrong exception");
            }
        }

        try
        {
            new DESedeParameters(weakKey);
            fail("no exception on weak key");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("attempt to create weak DESede key"))
            {
                fail("wrong exception");
            }
        }
    }

    public String getName()
    {
        return "DESede";
    }

    public static void main(
        String[]    args)
    {
        runTest(new DESedeTest());
    }
}
