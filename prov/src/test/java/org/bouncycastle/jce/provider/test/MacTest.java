package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

    static byte[]   input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f7220");

    static byte[]   output1 = Hex.decode("f1d30f68");
    static byte[]   output2 = Hex.decode("58d2e77e");
    static byte[]   output3 = Hex.decode("cd647403");

    static byte[]   keyBytesISO9797 = Hex.decode("7CA110454A1A6E570131D9619DC1376E");
    
    static byte[]   inputISO9797 = "Hello World !!!!".getBytes(); 
    
    static byte[]   outputISO9797 = Hex.decode("F09B856213BAB83B");
    
    static byte[]   inputDesEDE64 = "Hello World !!!!".getBytes(); 
    
    static byte[]   outputDesEDE64 = Hex.decode("862304d33af01096");
    
    public MacTest()
    {
    }

    private void aliasTest(SecretKey key, String primary, String[] aliases)
        throws Exception
    {
        Mac mac = Mac.getInstance(primary, "BC");

        //
        // standard DAC - zero IV
        //
        mac.init(key);

        mac.update(input, 0, input.length);

        byte[] ref = mac.doFinal();

        for (int i = 0; i != aliases.length; i++)
        {
            mac = Mac.getInstance(aliases[i], "BC");

            mac.init(key);

            mac.update(input, 0, input.length);

            byte[] out = mac.doFinal();
            if (!areEqual(out, ref))
            {
                fail("Failed - expected " + new String(Hex.encode(ref)) + " got " + new String(Hex.encode(out)));
            }
        }
    }

    public void performTest()
        throws Exception
    {
        SecretKey           key = new SecretKeySpec(keyBytes, "DES");
        byte[]              out;
        Mac                 mac;

        mac = Mac.getInstance("DESMac", "BC");

        //
        // standard DAC - zero IV
        //
        mac.init(key);

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!areEqual(out, output1))
        {
            fail("Failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // mac with IV.
        //
        mac.init(key, new IvParameterSpec(ivBytes));

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!areEqual(out, output2))
        {
            fail("Failed - expected " + new String(Hex.encode(output2)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // CFB mac with IV - 8 bit CFB mode
        //
        mac = Mac.getInstance("DESMac/CFB8", "BC");

        mac.init(key, new IvParameterSpec(ivBytes));

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!areEqual(out, output3))
        {
            fail("Failed - expected " + new String(Hex.encode(output3)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // ISO9797 algorithm 3 using DESEDE
        //
        key = new SecretKeySpec(keyBytesISO9797, "DESEDE");
        
        mac = Mac.getInstance("ISO9797ALG3", "BC");

        mac.init(key);

        mac.update(inputISO9797, 0, inputISO9797.length);

        out = mac.doFinal();

        if (!areEqual(out, outputISO9797))
        {
            fail("Failed - expected " + new String(Hex.encode(outputISO9797)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // 64bit DESede Mac
        //
        key = new SecretKeySpec(keyBytesISO9797, "DESEDE");
        
        mac = Mac.getInstance("DESEDE64", "BC");

        mac.init(key);

        mac.update(inputDesEDE64, 0, inputDesEDE64.length);

        out = mac.doFinal();

        if (!areEqual(out, outputDesEDE64))
        {
            fail("Failed - expected " + new String(Hex.encode(outputDesEDE64)) + " got " + new String(Hex.encode(out)));
        }

        aliasTest(new SecretKeySpec(keyBytesISO9797, "DESede"), "DESedeMac64withISO7816-4Padding",
            new String[] { "DESEDE64WITHISO7816-4PADDING", "DESEDEISO9797ALG1MACWITHISO7816-4PADDING", "DESEDEISO9797ALG1WITHISO7816-4PADDING" });

        aliasTest(new SecretKeySpec(keyBytesISO9797, "DESede"), "ISO9797ALG3WITHISO7816-4PADDING",
            new String[] { "ISO9797ALG3MACWITHISO7816-4PADDING" });

        aliasTest(new SecretKeySpec(keyBytes, "DES"), "DES64",
            new String[] { "DESMAC64" });
    }

    public String getName()
    {
        return "Mac";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new MacTest());
    }
}
