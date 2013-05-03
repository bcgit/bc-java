package org.bouncycastle.crypto.test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.HMacSP800DRBG;
import org.bouncycastle.crypto.prng.HashSP800DRBG;
import org.bouncycastle.crypto.prng.SP80090DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * DRBG Test
 */
public class HMacDRBGTest
    extends SimpleTest
{
    public String getName()
    {
        return this.getClass().getName();
    }

    public static void main(String[] args)
    {
        HMacDRBGTest test = new HMacDRBGTest();
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
        private String[] _ev;
        private boolean _magicalReseed = false;
        private List _ai = new ArrayList();

        public TestVector(String entropy, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
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
        
        public void setPersonalisationString(String p)
        {
            _personalisation = p;
        }
        
        public void setMagicalReseed()
        {
            _magicalReseed = true;
        }
        
        // some of the test vectors need to force a reseed after the first generate. 
        // it seems the easiest way to do this is pretend that you want the generate to
        // behave with prediction resistance (short of forcing reseed to go past RESEED_MAX)
        public boolean reseed()  
        {
            return _magicalReseed;
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
        
        public String[] expectedValue()
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

        TestVector tv = null;
        
        // line 7
        tv = new TestVector(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536",
                false,
                "2021222324",
                160,
                new String[] { "5A7D3B449F481CB38DF79AD2B1FCC01E57F8135E8C0B22CD0630BFB0127FB5408C8EFC17A929896E", "82cf772ec3e84b00fc74f5df104efbfb2428554e9ce367d03aeade37827fa8e9cb6a08196115d948" });
        rv.add(tv);
        
        return rv;
    }
        
    public void performTest() throws Exception
    {
        Collection<TestVector> tests = createTestVectorData();
        
        int c = 0;
        for (TestVector tv : tests)
        {
            tv.entropy();
            Digest digest = new SHA1Digest();
            EntropySource tes = new TestEntropySource(Hex.decode(tv.entropy()), tv.predictionResistance());
            byte[] nonce = Hex.decode(tv.nonce());
            byte[] personalisationString = Hex.decode(tv.personalisation());
            int securityStrength = tv.securityStrength();
            SP80090DRBG d = new HMacSP800DRBG(new HMac(digest), tes, tv.entropy().length()*4, nonce, personalisationString, tv.securityStrength());
            
            byte[] output = new byte[tv.expectedValue()[0].length() / 2];
            
            d.generate(output, tv.additionalInput(0), tv.predictionResistance());
            
            byte[] expected = Hex.decode(tv.expectedValue()[0]);

            String out = new String(Hex.encode(output));
            ++c;
            if (!areEqual(expected, output)) 
            {
                System.out.println("Test #"+c+" failed");
                fail("Test Vector Failed, expected "+tv.expectedValue()[0] +" got "+out);
            }

            output = new byte[320 / 8];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            expected = Hex.decode(tv.expectedValue()[1]);
            out = new String(Hex.encode(output));
            if (!areEqual(expected, output))
            {
                System.out.println("Test #"+c+" failed");
                fail("Test Vector Failed, expected "+tv.expectedValue()[1] +" got "+out);
            }
        }
        System.out.println("Total tests completed = "+c+" of "+tests.size());
    }
}
