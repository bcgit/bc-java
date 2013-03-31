package org.bouncycastle.crypto.test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DRBG;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.HashDerivationFunction;
import org.bouncycastle.crypto.prng.HashSP800DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * DRBG Test
 */
public class HashDRGBTest extends SimpleTest
{
    public String getName()
    {
        return this.getClass().getName();
    }

    public static void main(String[] args)
    {
        HashDRGBTest test = new HashDRGBTest();
        TestResult result = test.perform();
        
        if (result.getException() != null) 
        {
            result.getException().printStackTrace();
        }
        else
        {
            System.out.println("TEST PASSSED: "+result);
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
        private List _ai = new ArrayList();

        public TestVector(String entropy, boolean predictionResistance, String nonce, int securityStrength, String expected)
        {
            _entropy = entropy;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = "";
        }
        
        public void setAdditionalInput(String input)
        {
            _ai.add(input);
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

        public byte[] additionalInput(int position)
        {
            int len = _ai.size();
            byte[] rv;
            if (position >= len) {
                rv = null;
            } 
            else {
                rv = Hex.decode((String)(_ai.get(position)));
            }
            return rv; 
        }
    }
    
    private Collection createTestVectorData() 
    {
        Collection rv = new ArrayList();

        TestVector tv = new TestVector("a37a3e08d8393feb01c4d78cb6a4d1e210c288c89e9838176bc78946745f1c5bea44cf15e061601bfd45f7b3b95be924", true, "8243299805c0877e", 128, "a05002f98d5676e1b2e3b3d4686bb9055a830a39"); 
        rv.add(tv);
//        tv = new TestVector("55d201f2e3e2a6b42c95e73539ccf3ca51457ff8639e023be8a9c891ad318aa5b9bbf6b48d14d647d20708e7782bd7e0", true, "438bc46d0de7db69", 128, "aed4af08f9c1bda495338c305946d4c94452a785");
//        tv.setAdditionalInput("4bd19fd0f73d92373a3633375a367ee2");
//        tv.setAdditionalInput("b247178c21b266432594738d2430cb1d");
//        rv.add(tv);
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
            DRBG d = new HashSP800DRBG(hf, tes, nonce, personalisationString, securityStrength);
            
            byte[] output = new byte[20];
            
            int rv = d.generate(output, tv.additionalInput(0), true);
            String out = new String(Hex.encode(output));
            System.out.println(out);
            rv = d.generate(output, tv.additionalInput(1), true);
            out = new String(Hex.encode(output));
            System.out.println(out);
            
            byte[] expected = Hex.decode(tv.expectedValue());
            
            if (!areEqual(expected, output)) 
            {
                throw new Exception("Test Vector Failed, expected "+tv.expectedValue()+" got "+out);
            }
            System.out.println("Test Vector Passed, expected ; "+tv.expectedValue()+" got "+out);
        }
    }
}
