package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.digests.ShortenedDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * KDF1 tests - vectors from ISO 18033.
 */
public class KDF1GeneratorTest
    extends SimpleTest
{
    private byte[] seed1 = Hex.decode("d6e168c5f256a2dcff7ef12facd390f393c7a88d");
    private byte[] mask1 = Hex.decode(
            "0742ba966813af75536bb6149cc44fc256fd6406df79665bc31dc5"
          + "a62f70535e52c53015b9d37d412ff3c1193439599e1b628774c50d9c"
          + "cb78d82c425e4521ee47b8c36a4bcffe8b8112a89312fc04420a39de"
          + "99223890e74ce10378bc515a212b97b8a6447ba6a8870278");

    private byte[] seed2 = Hex.decode(
             "032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741" 
           + "52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
    private byte[] mask2 = Hex.decode(
             "5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca9" 
           + "75bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263c" 
           + "fccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e" 
           + "7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04");
    
    private byte[] seed3 = seed2;
    private byte[] mask3= Hex.decode(
             "09e2decf2a6e1666c2f6071ff4298305e2643fd510a2403db42a8743cb989de86e"
           + "668d168cbe604611ac179f819a3d18412e9eb45668f2923c087c12fee0c5a0d2a8aa"
           + "70185401fbbd99379ec76c663e875a60b4aacb1319fa11c3365a8b79a44669f26fb5"
           + "55c80391847b05eca1cb5cf8c2d531448d33fbaca19f6410ee1fcb");


    public KDF1GeneratorTest()
    {
    }
    
    public void performTest()
    {
        checkMask(1, new KDF1BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20)), seed1, mask1);
        checkMask(2, new KDF1BytesGenerator(new SHA1Digest()), seed2, mask2);
        checkMask(3, new KDF1BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20)), seed3, mask3);
        
        try
        {
            new KDF1BytesGenerator(new SHA1Digest()).generateBytes(new byte[10], 0, 20);
            
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
        
        kdf.init(new ISO18033KDFParameters(seed));
        
        kdf.generateBytes(data, 0, data.length);
        
        if (!areEqual(result, data))
        {
            fail("KDF1 failed generator test " + count);
        }
    }

    public String getName()
    {
        return "KDF1";
    }

    public static void main(
        String[]    args)
    {
        runTest(new KDF1GeneratorTest());
    }
}
