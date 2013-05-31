package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.ShortenedDigest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * KDF2 tests - vectors from ISO 18033.
 */
public class KDF2GeneratorTest
    extends SimpleTest
{
    private byte[] seed1 = Hex.decode("d6e168c5f256a2dcff7ef12facd390f393c7a88d");
    private byte[] mask1 = Hex.decode(
            "df79665bc31dc5a62f70535e52c53015b9d37d412ff3c119343959"
          + "9e1b628774c50d9ccb78d82c425e4521ee47b8c36a4bcffe8b8112a8"
          + "9312fc04420a39de99223890e74ce10378bc515a212b97b8a6447ba6"
          + "a8870278f0262727ca041fa1aa9f7b5d1cf7f308232fe861");
    
    private byte[] seed2 = Hex.decode(
             "032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741" 
           + "52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
    private byte[] mask2 = Hex.decode(
             "10a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb456" 
           + "68f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb13"
           + "19fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbac"
           + "a19f6410ee1fcb260892670e0814c348664f6a7248aaf998a3acc6");
    private byte[] adjustedMask2 = Hex.decode(
             "10a2403db42a8743cb989de86e668d168cbe6046e23ff26f741e87949a3bba1311ac1"
           + "79f819a3d18412e9eb45668f2923c087c1299005f8d5fd42ca257bc93e8fee0c5a0d2"
           + "a8aa70185401fbbd99379ec76c663e9a29d0b70f3fe261a59cdc24875a60b4aacb131"
           + "9fa11c3365a8b79a44669f26fba933d012db213d7e3b16349");

    private byte[] sha1Mask = Hex.decode(
             "0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840ff32"
           + "052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a2519"
           + "2985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837ee"
           + "a4e0a2f04b53ca8f50fb31225c1be2d0126c8c7a4753b0807");

    private byte[] seed3 = Hex.decode("CA7C0F8C3FFA87A96E1B74AC8E6AF594347BB40A");
    private byte[] mask3 = Hex.decode("744AB703F5BC082E59185F6D049D2D367DB245C2");

    private byte[] seed4 = Hex.decode("0499B502FC8B5BAFB0F4047E731D1F9FD8CD0D8881");
    private byte[] mask4 = Hex.decode("03C62280C894E103C680B13CD4B4AE740A5EF0C72547292F82DC6B1777F47D63BA9D1EA732DBF386");

    public KDF2GeneratorTest()
    {
    }
    
    public void performTest()
    {
        checkMask(1, new KDF2BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20)), seed1, mask1);
        checkMask(2, new KDF2BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20)), seed2, mask2);
        checkMask(3, new KDF2BytesGenerator(new SHA256Digest()), seed2, adjustedMask2);
        checkMask(4, new KDF2BytesGenerator(new SHA1Digest()), seed2, sha1Mask);
        checkMask(5, new KDF2BytesGenerator(new SHA1Digest()), seed3, mask3);
        checkMask(6, new KDF2BytesGenerator(new SHA1Digest()), seed4, mask4);
        
        try
        {
            new KDF2BytesGenerator(new SHA1Digest()).generateBytes(new byte[10], 0, 20);
            
            fail("short input array not caught");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
    }
    
    private void checkMask(
        int                count,
        DerivationFunction kdf,
        byte[]             seed,
        byte[]             result)
    {
        byte[]             data = new byte[result.length];
        
        kdf.init(new KDFParameters(seed, new byte[0]));
        
        kdf.generateBytes(data, 0, data.length);
        
        if (!areEqual(result, data))
        {
            fail("KDF2 failed generator test " + count);
        }
    }

    public String getName()
    {
        return "KDF2";
    }

    public static void main(
        String[]    args)
    {
        runTest(new KDF2GeneratorTest());
    }
}
