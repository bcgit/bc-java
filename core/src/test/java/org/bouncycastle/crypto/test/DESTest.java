package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

class DESParityTest
    extends SimpleTest
{
    public String getName()
    {
        return "DESParityTest";
    }

    public void performTest()
    {
        byte[]  k1In = { (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                        (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff };
        byte[]  k1Out = { (byte)0xfe, (byte)0xfe, (byte)0xfe, (byte)0xfe,
                        (byte)0xfe, (byte)0xfe, (byte)0xfe, (byte)0xfe };

        byte[]  k2In = { (byte)0xef, (byte)0xcb, (byte)0xda, (byte)0x4f,
                        (byte)0xaa, (byte)0x99, (byte)0x7f, (byte)0x63 };
        byte[]  k2Out = { (byte)0xef, (byte)0xcb, (byte)0xda, (byte)0x4f,
                        (byte)0xab, (byte)0x98, (byte)0x7f, (byte)0x62 };

        DESParameters.setOddParity(k1In);

        for (int i = 0; i != k1In.length; i++)
        {
            if (k1In[i] != k1Out[i])
            {
                fail("Failed " 
                    + "got " + new String(Hex.encode(k1In))
                    + " expected " + new String(Hex.encode(k1Out)));
            }
        }

        DESParameters.setOddParity(k2In);

        for (int i = 0; i != k2In.length; i++)
        {
            if (k2In[i] != k2Out[i])
            {
                fail("Failed " 
                    + "got " + new String(Hex.encode(k2In))
                    + " expected " + new String(Hex.encode(k2Out)));
            }
        }
    }
}

class KeyGenTest
    extends SimpleTest
{
    public String getName()
    {
        return "KeyGenTest";
    }

    public void performTest()
    {
        DESKeyGenerator keyGen = new DESKeyGenerator();
        
        keyGen.init(new KeyGenerationParameters(new SecureRandom(), 56));
        
        byte[] kB = keyGen.generateKey();
        
        if (kB.length != 8)
        {
            fail("DES bit key wrong length.");
        }
    }
}

class DESParametersTest
    extends SimpleTest
{
    static private byte[] weakKeys =
     {
         (byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01, (byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01,
         (byte)0x1f,(byte)0x1f,(byte)0x1f,(byte)0x1f, (byte)0x0e,(byte)0x0e,(byte)0x0e,(byte)0x0e,
         (byte)0xe0,(byte)0xe0,(byte)0xe0,(byte)0xe0, (byte)0xf1,(byte)0xf1,(byte)0xf1,(byte)0xf1,
         (byte)0xfe,(byte)0xfe,(byte)0xfe,(byte)0xfe, (byte)0xfe,(byte)0xfe,(byte)0xfe,(byte)0xfe,
         /* semi-weak keys */
         (byte)0x01,(byte)0xfe,(byte)0x01,(byte)0xfe, (byte)0x01,(byte)0xfe,(byte)0x01,(byte)0xfe,
         (byte)0x1f,(byte)0xe0,(byte)0x1f,(byte)0xe0, (byte)0x0e,(byte)0xf1,(byte)0x0e,(byte)0xf1,
         (byte)0x01,(byte)0xe0,(byte)0x01,(byte)0xe0, (byte)0x01,(byte)0xf1,(byte)0x01,(byte)0xf1,
         (byte)0x1f,(byte)0xfe,(byte)0x1f,(byte)0xfe, (byte)0x0e,(byte)0xfe,(byte)0x0e,(byte)0xfe,
         (byte)0x01,(byte)0x1f,(byte)0x01,(byte)0x1f, (byte)0x01,(byte)0x0e,(byte)0x01,(byte)0x0e,
         (byte)0xe0,(byte)0xfe,(byte)0xe0,(byte)0xfe, (byte)0xf1,(byte)0xfe,(byte)0xf1,(byte)0xfe,
         (byte)0xfe,(byte)0x01,(byte)0xfe,(byte)0x01, (byte)0xfe,(byte)0x01,(byte)0xfe,(byte)0x01,
         (byte)0xe0,(byte)0x1f,(byte)0xe0,(byte)0x1f, (byte)0xf1,(byte)0x0e,(byte)0xf1,(byte)0x0e,
         (byte)0xe0,(byte)0x01,(byte)0xe0,(byte)0x01, (byte)0xf1,(byte)0x01,(byte)0xf1,(byte)0x01,
         (byte)0xfe,(byte)0x1f,(byte)0xfe,(byte)0x1f, (byte)0xfe,(byte)0x0e,(byte)0xfe,(byte)0x0e,
         (byte)0x1f,(byte)0x01,(byte)0x1f,(byte)0x01, (byte)0x0e,(byte)0x01,(byte)0x0e,(byte)0x01,
         (byte)0xfe,(byte)0xe0,(byte)0xfe,(byte)0xe0, (byte)0xfe,(byte)0xf1,(byte)0xfe,(byte)0xf1
     };

    public String getName()
    {
        return "DESParameters";
    }

    public void performTest() throws Exception
    {
        try
        {
            DESParameters.isWeakKey(new byte[4], 0);
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
            new DESParameters(weakKeys);
            fail("no exception on weak key");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("attempt to create weak DES key"))
            {
                fail("wrong exception");
            }
        }

        for (int i = 0; i != weakKeys.length; i += 8)
        {
            if (!DESParameters.isWeakKey(weakKeys, i))
            {
                fail("weakKey test failed");
            }
        }
    }
}

/**
 * DES tester - vectors from <a href=https://www.itl.nist.gov/fipspubs/fip81.htm>FIPS 81</a>
 */
public class DESTest
    extends CipherTest
{
    static String   input1 = "4e6f77206973207468652074696d6520666f7220616c6c20";
    static String   input2 = "4e6f7720697320746865";
    static String   input3 = "4e6f7720697320746865aabbcc";

    static SimpleTest[]   tests = 
            {
                new BlockCipherVectorTest(0, new DESEngine(),
                        new KeyParameter(Hex.decode("0123456789abcdef")),
                        input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
                new BlockCipherVectorTest(1, new CBCBlockCipher(new DESEngine()),
                        new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")),
                        input1, "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"),
                new BlockCipherVectorTest(2, new CFBBlockCipher(new DESEngine(), 8),
                        new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")),
                        input2, "f31fda07011462ee187f"),
                new BlockCipherVectorTest(3, new CFBBlockCipher(new DESEngine(), 64),
                        new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")),
                        input1, "f3096249c7f46e51a69e839b1a92f78403467133898ea622"),
                new BlockCipherVectorTest(4, new OFBBlockCipher(new DESEngine(), 8),
                        new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")),
                        input2, "f34a2850c9c64985d684"),
                new BlockCipherVectorTest(5, new CFBBlockCipher(new DESEngine(), 64),
                        new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")),
                        input3, "f3096249c7f46e51a69e0954bf"),
                new BlockCipherVectorTest(6, new OFBBlockCipher(new DESEngine(), 64),
                        new ParametersWithIV(new KeyParameter(Hex.decode("0123456789abcdef")), Hex.decode("1234567890abcdef")),
                        input3, "f3096249c7f46e5135f2c0eb8b"),
                new DESParityTest(),
                new DESParametersTest(),
                new KeyGenTest()
            };

    public DESTest()
    {
        super(tests, new DESEngine(), new KeyParameter(new byte[8]));
    }

    public String getName()
    {
        return "DES";
    }

    public static void main(
        String[]    args)
    {
        runTest(new DESTest());
    }
}
