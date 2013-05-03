package org.bouncycastle.crypto.test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.prng.CTRSP800DRBG;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * DRBG Test
 */
public class CTRDRGBTest extends SimpleTest
{
    public String getName()
    {
        return "DRGBCTRTest";
    }

    public static void main(String[] args)
    {
        CTRDRGBTest test = new CTRDRGBTest();
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

        // line 3246
        TestVector tv = new TestVector(
                "d9dc92450a03fa663613395037d50655136b3088ebe84cd3cc99d39733e2c88fa6528dff60b1f934f1ee472a20572eb7",
                true, 
                "d3ec0c67136ee08c", 
                128, 
                "e7ce8192f1c18613cd5d7ab11ca22da1"); 
        rv.add(tv);
        return rv;
        
    }
        
    public void performTest() throws Exception
    {
        Collection<TestVector> tests = createTestVectorData();
        
        for (TestVector tv : tests)
        {
            tv.entropy();
            BlockCipher engine = new AESFastEngine();
            EntropySource tes = new TestEntropySource(Hex.decode(tv.entropy()), tv.predictionResistance());
            byte[] nonce = Hex.decode(tv.nonce());
            byte[] personalisationString = Hex.decode(tv.personalisation());
            int securityStrength = tv.securityStrength();
            CTRSP800DRBG d = new CTRSP800DRBG(engine, 256, 256, tes, 256, nonce, personalisationString, securityStrength);
            
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
