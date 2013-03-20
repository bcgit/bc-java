package org.bouncycastle.crypto.test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

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

    private class TestVector 
    {
        
        private String _entropy;
        private boolean _pr;
        private String _nonce;
        private String _personalisation;
        private int _ss;
        private String _ev;

        public TestVector(String entropy, boolean predictionResistance, String nonce, String personalisation, int securityStrength, String expected)
        {
            _entropy = entropy;
            _pr = predictionResistance;
            _nonce = nonce;
            _personalisation = personalisation;
            _ss = securityStrength;
            _ev = expected;
        }
        
        public String entropy()
        {
            return _entropy;
        }
        
        public boolean predictionResistance()
        {
            return _pr;
        }
        
        public String nonce()
        {
            return _nonce;
        }
        
        public String personalisation() 
        {
            return _personalisation;
        }
        
        public int securityStrength() 
        {
            return _ss;
        }
        
        public String expectedValue() 
        {
            return _ev;
        }
    }
    
    private Collection createTestVectorData() 
    {
        Collection rv = new ArrayList();

        TestVector tv = new TestVector("a37a3e08d8393feb01c4d78cb6a4d1e210c288c89e9838176bc78946745f1c5bea44cf15e061601bfd45f7b3b95be924", true, "8243299805c0877e", "", 128, "a05002f98d5676e1b2e3b3d4686bb9055a830a39"); 

        rv.add(tv);
        
        return rv;
        
    }
        
    public void performTest() throws Exception
    {
        Collection<TestVector> tests = createTestVectorData();
        
        for (TestVector tv : tests)
        {
            tv.entropy();
            Digest digest = new SHA1Digest();
            HashDerivationFunction hf = new HashDerivationFunction(digest, 440);
            EntropySource tes = new TestEntropySource(Hex.decode(tv.entropy()), tv.predictionResistance());
            byte[] nonce = Hex.decode(tv.nonce());
            byte[] personalisationString = Hex.decode(tv.personalisation());
            int securityStrength = tv.securityStrength();
            DRBG d = new SP800DRBG(hf, tes, nonce, personalisationString, securityStrength);
            
            byte[] output = new byte[20];
            
            int rv = d.generate(output, null, true);
            String out = new String(Hex.encode(output));
            System.out.println(out);
            rv = d.generate(output, null, true);
            out = new String(Hex.encode(output));
            System.out.println(out);
            
            byte[] expected = Hex.decode(tv.expectedValue());
            
            if (!areEqual(expected, output)) 
            {
                throw new Exception("Test Vector Failed, expected "+tv.expectedValue()+" got "+out);
            }
        }
    }
}
