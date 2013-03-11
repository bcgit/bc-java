package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.BasicEntropySource;
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
        Digest digest = new SHA512Digest();
        HashDerivationFunction hf = new HashDerivationFunction(digest, 888);
        EntropySource entropySource = new BasicEntropySource(new SecureRandom(), false);
        byte[] nonce = new byte[0];
        byte[] personalisationString = new byte[0];
        int securityStrength = 128;
        DRBG d = new SP800DRBG(hf, entropySource, nonce, personalisationString, securityStrength);
        
        byte[] output = new byte[10];
        
        int rv = d.generate(output, null, 0, 0);
        String out = new String(Hex.encode(output));
        System.out.println(out);
        for (int i=out.length()-1;i>=0;i--) 
        {
            if (out.charAt(i) != '0') 
            {
                System.out.println(i);
                return;
            }
        }
    }
}
