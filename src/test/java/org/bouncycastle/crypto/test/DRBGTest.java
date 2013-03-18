package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DRBG;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.HashDerivationFunction;
import org.bouncycastle.crypto.prng.SP800DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * DRBG Test
 */
public class DRBGTest extends SimpleTest
{
    public String getName()
    {
        return "DRGBTest";
    }

    public static void main(String[] args)
    {
        DRBGTest test = new DRBGTest();
        TestResult result = test.perform();
        
        if (result.getException() != null) 
        {
            result.getException().printStackTrace();
        }
        else
        {
            System.out.println(result);
        }
    }

    public void performTest() throws Exception
    {
        Digest digest = new SHA1Digest();
        HashDerivationFunction hf = new HashDerivationFunction(digest, 440);
        EntropySource tes = new TestEntropySource(Hex.decode("a37a3e08d8393feb01c4d78cb6a4d1e210c288c89e9838176bc78946745f1c5bea44cf15e061601bfd45f7b3b95be924"), true);
        byte[] nonce = Hex.decode("8243299805c0877e");
        byte[] personalisationString = new byte[0];
        int securityStrength = 128;
        DRBG d = new SP800DRBG(hf, tes, nonce, personalisationString, securityStrength);
        
        byte[] output = new byte[20];
        
        int rv = d.generate(output, null, true);
        String out = new String(Hex.encode(output));
        
        System.out.println(out);

        rv = d.generate(output, null, true);
        out = new String(Hex.encode(output));
        
        System.out.println(out);

    }
}
