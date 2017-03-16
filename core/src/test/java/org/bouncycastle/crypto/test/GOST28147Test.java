package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GOFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class GOST28147Test
     extends CipherTest
{
    static String   input1 =  "0000000000000000";
    static String   output1 = "1b0bbc32cebcab42";
    static String   input2 =  "bc350e71aac5f5c2";
    static String   output2 = "d35ab653493b49f5";
    static String   input3 =  "bc350e71aa11345709acde";
    static String   output3 = "8824c124c4fd14301fb1e8";
    static String   input4 =  "000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f";
    static String   output4 = "29b7083e0a6d955ca0ec5b04fdb4ea41949f1dd2efdf17baffc1780b031f3934";

    static byte TestSBox[] = {
            0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
            0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
            0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
            0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
            0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
            0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
            0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
            0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0
    };

    static byte[] TestSBox_1 =
    {
         0xE, 0x3, 0xC, 0xD, 0x1, 0xF, 0xA, 0x9, 0xB, 0x6, 0x2, 0x7, 0x5, 0x0, 0x8, 0x4,
         0xD, 0x9, 0x0, 0x4, 0x7, 0x1, 0x3, 0xB, 0x6, 0xC, 0x2, 0xA, 0xF, 0xE, 0x5, 0x8,
         0x8, 0xB, 0xA, 0x7, 0x1, 0xD, 0x5, 0xC, 0x6, 0x3, 0x9, 0x0, 0xF, 0xE, 0x2, 0x4,
         0xD, 0x7, 0xC, 0x9, 0xF, 0x0, 0x5, 0x8, 0xA, 0x2, 0xB, 0x6, 0x4, 0x3, 0x1, 0xE,
         0xB, 0x4, 0x6, 0x5, 0x0, 0xF, 0x1, 0xC, 0x9, 0xE, 0xD, 0x8, 0x3, 0x7, 0xA, 0x2,
         0xD, 0xF, 0x9, 0x4, 0x2, 0xC, 0x5, 0xA, 0x6, 0x0, 0x3, 0x8, 0x7, 0xE, 0x1, 0xB,
         0xF, 0xE, 0x9, 0x5, 0xB, 0x2, 0x1, 0x8, 0x6, 0x0, 0xD, 0x3, 0x4, 0x7, 0xC, 0xA,
         0xA, 0x3, 0xE, 0x2, 0x0, 0x1, 0x4, 0x6, 0xB, 0x8, 0xC, 0x7, 0xD, 0x5, 0xF, 0x9
    };

    static SimpleTest[]   tests =
    {   new BlockCipherVectorTest(1, new GOST28147Engine(),
            new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")),
                input1, output1),
        new BlockCipherVectorTest(2, new CBCBlockCipher(new GOST28147Engine()),
            new ParametersWithIV(new KeyParameter(Hex.decode("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")),
                                 Hex.decode("1234567890abcdef")), input2, output2),
        new BlockCipherVectorTest(3, new GOFBBlockCipher(new GOST28147Engine()),
            new ParametersWithIV(new KeyParameter(Hex.decode("0011223344556677889900112233445566778899001122334455667788990011")),
                                     Hex.decode("1234567890abcdef")), //IV
                                     input3, output3),
        new BlockCipherVectorTest(4, new CFBBlockCipher(new GOST28147Engine(), 64),
            new ParametersWithIV(new KeyParameter(Hex.decode("aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5")),
                                 Hex.decode("aafd12f659cae634")), input4, output4),

        //tests with parameters, set S-box.
        new BlockCipherVectorTest(5, new GOST28147Engine(),
            new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")),//key , default parameter S-box set to D-Test
                input1, output1),
        new BlockCipherVectorTest(6, new CFBBlockCipher(new GOST28147Engine(), 64),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       GOST28147Engine.getSBox("D-Test")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "b587f7a0814c911d"), //encrypt message
        new BlockCipherVectorTest(7, new CFBBlockCipher(new GOST28147Engine(), 64),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       GOST28147Engine.getSBox("E-Test")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "e8287f53f991d52b"), //encrypt message
        new BlockCipherVectorTest(8, new CFBBlockCipher(new GOST28147Engine(), 64),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       GOST28147Engine.getSBox("E-A")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "c41009dba22ebe35"), //encrypt message
        new BlockCipherVectorTest(9, new CFBBlockCipher(new GOST28147Engine(), 8),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       GOST28147Engine.getSBox("E-B")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "80d8723fcd3aba28"), //encrypt message
        new BlockCipherVectorTest(10, new CFBBlockCipher(new GOST28147Engine(), 8),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       GOST28147Engine.getSBox("E-C")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "739f6f95068499b5"), //encrypt message
        new BlockCipherVectorTest(11, new CFBBlockCipher(new GOST28147Engine(), 8),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       GOST28147Engine.getSBox("E-D")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "4663f720f4340f57"), //encrypt message
        new BlockCipherVectorTest(12, new CFBBlockCipher(new GOST28147Engine(), 8),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       GOST28147Engine.getSBox("D-A")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "5bb0a31d218ed564"), //encrypt message
        new BlockCipherVectorTest(13, new CFBBlockCipher(new GOST28147Engine(), 8),
            new ParametersWithIV(
                new ParametersWithSBox(
                       new KeyParameter(Hex.decode("546d203368656c326973652073736e62206167796967747473656865202c3d73")), //key
                       TestSBox), //set own S-box
                Hex.decode("1234567890abcdef")), //IV
                "0000000000000000", //input message
                "c3af96ef788667c5"), //encrypt message
        new BlockCipherVectorTest(14, new GOFBBlockCipher(new GOST28147Engine()),
            new ParametersWithIV(
                new ParametersWithSBox(
                        new KeyParameter(Hex.decode("4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d")), //key
                        GOST28147Engine.getSBox("E-A")), //type S-box
                Hex.decode("1234567890abcdef")), //IV
                "bc350e71aa11345709acde",  //input message
                "1bcc2282707c676fb656dc"), //encrypt message
        new BlockCipherVectorTest(15, new GOFBBlockCipher(new GOST28147Engine()),
            new ParametersWithIV(
                new ParametersWithSBox(
                    new KeyParameter(Hex.decode("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993")), //key
                    TestSBox_1), //type, IV, S-box
                Hex.decode("8001069080010690")),
            "094C912C5EFDD703D42118971694580B", //input message
            "2707B58DF039D1A64460735FFE76D55F"), //encrypt message
        new BlockCipherVectorTest(16, new GOFBBlockCipher(new GOST28147Engine()),
            new ParametersWithIV(
                new ParametersWithSBox(
                    new KeyParameter(Hex.decode("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993")), //key
                    TestSBox_1), //type, S-box
                    Hex.decode("800107A0800107A0")),
            "FE780800E0690083F20C010CF00C0329", //input message
            "9AF623DFF948B413B53171E8D546188D"), //encrypt message
        new BlockCipherVectorTest(17, new GOFBBlockCipher(new GOST28147Engine()),
            new ParametersWithIV(
                new ParametersWithSBox(
                    new KeyParameter(Hex.decode("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993")), //key
                    TestSBox_1), //type, S-box
                    Hex.decode("8001114080011140")),
            "D1088FD8C0A86EE8F1DCD1088FE8C058", //input message
            "62A6B64D12253BCD8241A4BB0CFD3E7C"), //encrypt message
        new BlockCipherVectorTest(18, new GOFBBlockCipher(new GOST28147Engine()),
            new ParametersWithIV(
                new ParametersWithSBox(
                    new KeyParameter(Hex.decode("0A43145BA8B9E9FF0AEA67D3F26AD87854CED8D9017B3D33ED81301F90FDF993")), //key
                    TestSBox_1), //type, IV, S-box
                    Hex.decode("80011A3080011A30")),
            "D431FACD011C502C501B500A12921090", //input message
            "07313C89D302FF73234B4A0506AB00F3"), //encrypt message
    };

    static private final int GOST28147_KEY_LENGTH = 32;
    
    private byte[] generateKey(byte[] startkey)
    {
        byte[]  newKey = new byte[GOST28147_KEY_LENGTH];

        GOST3411Digest digest = new GOST3411Digest();
        
        digest.update(startkey, 0, startkey.length);
        digest.doFinal(newKey, 0);

        return newKey;
    }
    
    GOST28147Test()
    {
        super(tests, new GOST28147Engine(), new KeyParameter(new byte[32]));
    }
    
    public void performTest()
        throws Exception
    {
        super.performTest();

        //advanced tests with GOST28147KeyGenerator:
        //encrypt on hesh message; ECB mode:
        byte[] in     = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");
        byte[] output = Hex.decode("8ad3c8f56b27ff1fbd46409359bdc796bc350e71aac5f5c0");
        byte[] out    = new byte[in.length];

        byte[] key = generateKey(Hex.decode("0123456789abcdef"));  //!!! heshing start_key - get 256 bits !!!
//        System.out.println(new String(Hex.encode(key)));
        CipherParameters  param = new ParametersWithSBox(new KeyParameter(key), GOST28147Engine.getSBox("E-A"));
        //CipherParameters  param = new GOST28147Parameters(key,"D-Test");
        BufferedBlockCipher cipher = new BufferedBlockCipher(new GOST28147Engine());

        cipher.init(true, param);
        int len1 = cipher.processBytes(in, 0, in.length, out, 0);
        try
        {
            cipher.doFinal(out, len1);
        }
        catch (CryptoException e)
        {
            fail("failed - exception " + e.toString(), e);
        }
        if (out.length != output.length)
        {
            fail("failed - "
                    + "expected " + new String(Hex.encode(output)) + " got "
                    + new String(Hex.encode(out)));
        }
        for (int i = 0; i != out.length; i++)
        {
            if (out[i] != output[i])
            {
                fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
            }
        }


        //encrypt on hesh message; CFB mode:
        in     = Hex.decode("bc350e71aac5f5c2");
        output = Hex.decode("0ebbbafcf38f14a5");
        out    = new byte[in.length];

        key = generateKey(Hex.decode("0123456789abcdef"));  //!!! heshing start_key - get 256 bits !!!
        param = new ParametersWithIV(new ParametersWithSBox(
                                                             new KeyParameter(key), //key
                                                             GOST28147Engine.getSBox("E-A")), //type S-box
                                     Hex.decode("1234567890abcdef")); //IV

        cipher = new BufferedBlockCipher(new CFBBlockCipher(new GOST28147Engine(), 64));

        cipher.init(true, param);
        len1 = cipher.processBytes(in, 0, in.length, out, 0);
        try
        {
            cipher.doFinal(out, len1);
        }
        catch (CryptoException e)
        {
            fail("failed - exception " + e.toString(), e);
        }
        if (out.length != output.length)
        {
            fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }
        for (int i = 0; i != out.length; i++)
        {
            if (out[i] != output[i])
            {
                fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
            }
        }


        //encrypt on hesh message; CFB mode:
        in     = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");
        output = Hex.decode("64988982819f0a1655e226e19ecad79d10cc73bac95c5d7da034786c12294225");
        out    = new byte[in.length];

        key = generateKey(Hex.decode("aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5"));  //!!! heshing start_key - get 256 bits !!!
        param = new ParametersWithIV(new ParametersWithSBox(
                                                             new KeyParameter(key), //key
                                                             GOST28147Engine.getSBox("E-A")), //type S-box
                                     Hex.decode("aafd12f659cae634")); //IV

        cipher = new BufferedBlockCipher(new CFBBlockCipher(new GOST28147Engine(), 64));

        cipher.init(true, param);
        len1 = cipher.processBytes(in, 0, in.length, out, 0);

        cipher.doFinal(out, len1);

        if (out.length != output.length)
        {
            fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }
        
        for (int i = 0; i != out.length; i++)
        {
            if (out[i] != output[i])
            {
                fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
            }
        }

        //encrypt on hesh message; OFB mode:
        in     = Hex.decode("bc350e71aa11345709acde");
        output = Hex.decode("1bcc2282707c676fb656dc");
        out    = new byte[in.length];

        key = generateKey(Hex.decode("0123456789abcdef"));  //!!! heshing start_key - get 256 bits !!!
        param = new ParametersWithIV(new ParametersWithSBox(
                                                             new KeyParameter(key), //key
                                                             GOST28147Engine.getSBox("E-A")), //type S-box
                                     Hex.decode("1234567890abcdef")); //IV

        cipher = new BufferedBlockCipher(new GOFBBlockCipher(new GOST28147Engine()));

        cipher.init(true, param);
        len1 = cipher.processBytes(in, 0, in.length, out, 0);

        cipher.doFinal(out, len1);

        if (out.length != output.length)
        {
            fail("failed - " + "expected "
                    + new String(Hex.encode(output)) + " got "
                    + new String(Hex.encode(out)));
        }
        for (int i = 0; i != out.length; i++)
        {
            if (out[i] != output[i])
            {
                fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
            }
        }

        // key reuse test
        param = new ParametersWithIV(null, // key and sbox reused
                           Hex.decode("1234567890abcdef")); //IV

        cipher.init(true, param);
        len1 = cipher.processBytes(in, 0, in.length, out, 0);

        cipher.doFinal(out, len1);

        if (out.length != output.length)
        {
            fail("failed - " + "expected "
                    + new String(Hex.encode(output)) + " got "
                    + new String(Hex.encode(out)));
        }
        for (int i = 0; i != out.length; i++)
        {
            if (out[i] != output[i])
            {
                fail("failed - " + "expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
            }
        }
    }

    public String getName()
    {
        return "GOST28147";
    }

    public static void main(
        String[]    args)
    {
        runTest(new GOST28147Test());
    }
}
