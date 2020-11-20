package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CFBBlockCipherMac;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * MAC tester - vectors from 
 * <a href=https://www.itl.nist.gov/fipspubs/fip81.htm>FIP 81</a> and 
 * <a href=https://www.itl.nist.gov/fipspubs/fip113.htm>FIP 113</a>.
 */
public class MacTest
    extends SimpleTest
{
    static byte[]   keyBytes = Hex.decode("0123456789abcdef");
    static byte[]   ivBytes = Hex.decode("1234567890abcdef");

    static byte[]   input1 = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f7220");

    static byte[]   output1 = Hex.decode("f1d30f68");
    static byte[]   output2 = Hex.decode("58d2e77e");
    static byte[]   output3 = Hex.decode("cd647403");

    //
    // these aren't NIST vectors, just for regression testing.
    //
    static byte[]   input2 = Hex.decode("3736353433323120");

    static byte[]   output4 = Hex.decode("3af549c9");
    static byte[]   output5 = Hex.decode("188fbdd5");
    static byte[]   output6 = Hex.decode("7045eecd");

    public MacTest()
    {
    }

    public void performTest()
    {
        KeyParameter        key = new KeyParameter(keyBytes);
        BlockCipher         cipher = new DESEngine();
        Mac                 mac = new CBCBlockCipherMac(cipher);

        //
        // standard DAC - zero IV
        //
        mac.init(key);

        mac.update(input1, 0, input1.length);

        byte[]  out = new byte[4];

        mac.doFinal(out, 0);

        if (!areEqual(out, output1))
        {
            fail("Failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // mac with IV.
        //
        ParametersWithIV    param = new ParametersWithIV(key, ivBytes);

        mac.init(param);

        mac.update(input1, 0, input1.length);

        out = new byte[4];

        mac.doFinal(out, 0);

        if (!areEqual(out, output2))
        {
            fail("Failed - expected " + new String(Hex.encode(output2)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // CFB mac with IV - 8 bit CFB mode
        //
        param = new ParametersWithIV(key, ivBytes);

        mac = new CFBBlockCipherMac(cipher);

        mac.init(param);

        mac.update(input1, 0, input1.length);

        out = new byte[4];

        mac.doFinal(out, 0);

        if (!areEqual(out, output3))
        {
            fail("Failed - expected " + new String(Hex.encode(output3)) + " got " + new String(Hex.encode(out)));
        }

        //
        // word aligned data - zero IV
        //
        mac.init(key);

        mac.update(input2, 0, input2.length);

        out = new byte[4];

        mac.doFinal(out, 0);

        if (!areEqual(out, output4))
        {
            fail("Failed - expected " + new String(Hex.encode(output4)) + " got " + new String(Hex.encode(out)));
        }

        //
        // word aligned data - zero IV - CBC padding
        //
        mac = new CBCBlockCipherMac(cipher, new PKCS7Padding());

        mac.init(key);

        mac.update(input2, 0, input2.length);

        out = new byte[4];

        mac.doFinal(out, 0);

        if (!areEqual(out, output5))
        {
            fail("Failed - expected " + new String(Hex.encode(output5)) + " got " + new String(Hex.encode(out)));
        }

        //
        // non-word aligned data - zero IV - CBC padding
        //
        mac.reset();

        mac.update(input1, 0, input1.length);

        out = new byte[4];

        mac.doFinal(out, 0);

        if (!areEqual(out, output6))
        {
            fail("Failed - expected " + new String(Hex.encode(output6)) + " got " + new String(Hex.encode(out)));
        }

        //
        // non-word aligned data - zero IV - CBC padding
        //
        mac.init(key);

        mac.update(input1, 0, input1.length);

        out = new byte[4];

        mac.doFinal(out, 0);

        if (!areEqual(out, output6))
        {
            fail("Failed - expected " + new String(Hex.encode(output6)) + " got " + new String(Hex.encode(out)));
        }
    }

    public String getName()
    {
        return "Mac";
    }

    public static void main(
        String[]    args)
    {
        runTest(new MacTest());
    }
}
