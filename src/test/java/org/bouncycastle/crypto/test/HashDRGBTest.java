package org.bouncycastle.crypto.test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.HashSP800DRBG;
import org.bouncycastle.crypto.prng.SP80090DRBG;
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
        private boolean _magicalReseed = false;
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

        TestVector tv = null;
        
        // line 7
        tv = new TestVector(
                "a37a3e08d8393feb01c4d78cb6a4d1e210c288c89e9838176bc78946745f1c5bea44cf15e061601bfd45f7b3b95be924", 
                true, 
                "8243299805c0877e", 
                128, 
                "a05002f98d5676e1b2e3b3d4686bb9055a830a39"); 
        rv.add(tv);        

        // line 27
        tv = new TestVector(
                "28955584d8f219b7d23fa72c18e02d100af4889bdc691b9739ececa1dc77cb84aa87ff265d7db170d81cdd8ff05602bf", 
                true, 
                "72847c01a49c2686", 
                128, 
                "085bfc190fdc6017c00c5beb6678878f6a12375a"); 
        rv.add(tv); 
        
        // line 40
        tv = new TestVector(
                "9a7ff1e2cc253c9699f307b82c14bddf67f18acf6e1bd8accb4bc3cacfcd81fd681138d4ff1a53baea0794a6216c443b", 
                true, 
                "1bef424a7dc0faea", 
                128, 
                "eb829d215ac55efd6e964f671b7587e3c1439ce8"); 
        rv.add(tv); 
        
        // line 217 of Hash_DRBG.txt
        tv = new TestVector(
                "55d201f2e3e2a6b42c95e73539ccf3ca51457ff8639e023be8a9c891ad318aa5b9bbf6b48d14d647d20708e7782bd7e0", // entropy 
                true, // prediction resistance 
                "438bc46d0de7db69", // nonce
                128, // security strength
                "aed4af08f9c1bda495338c305946d4c94452a785"); // result
        tv.setAdditionalInput("4bd19fd0f73d92373a3633375a367ee2");  // additional input
        tv.setAdditionalInput("b247178c21b266432594738d2430cb1d");  // additional input
        rv.add(tv);
        
        // line 230 of Hash_DRBG.txt
        tv = new TestVector(
                "78df90663fdf3a983cb8a3dec289e53e51500dd8fdd0d720cde174e7beeb6891f3b8b607e81274b03f69b87204c922a8", // entropy 
                true, // prediction resistance 
                "496caad48119623f", // nonce
                128, // security strength
                "c2b224d922e5c5553143e8c72ea2482984506593"); // result
        tv.setAdditionalInput("4bdc2db0916e671c1f6ede8d6af05cce");  // additional input
        tv.setAdditionalInput("f79216128f3ec4d96194de0cfccba17d");  // additional input
        rv.add(tv);
        
        // line 243 of Hash_DRBG.txt
        tv = new TestVector(
                "addcbba340a3ade464d16723e5df651c73a91ca11a672f3ffc29aa7bdc14d0ce17ef0235e1ce1779e38541b377dc6154", // entropy 
                true, // prediction resistance 
                "71856d19a46fe11d", // nonce
                128, // security strength
                "d91b6fdedd5369ef50c743d24599e358b557711e"); // result
        tv.setAdditionalInput("f6f8eb121f776e339ddfdbf47bbd7d4c");  // additional input
        tv.setAdditionalInput("f3a685a580fb8b58c82162bdf49d5a75");  // additional input
        rv.add(tv);

        // line 419 of Hash_DRBG.txt
        tv = new TestVector(
                "2616ae30ee1bc618f44cd700deabafb4602564ed770090946e25ffcd6d6de597709d0bf81e88c6af6b3996985c94feec", // entropy 
                true, // prediction resistance 
                "20c760bedbdc6f8e", // nonce
                128, // security strength
                "dc675ef7de1a45b14bfc2169848e51fda0db1c9c"); // result
        tv.setPersonalisationString("0bdd90e6bedfc8d611a3fd2409604086");
        rv.add(tv);        
        
        // line 621 of Hash_DRBG.txt
        tv = new TestVector(
                "d236a5273173dd114f93bde231a59113c9839e16f61c0fb2ec6031a9cba9367a4e8c499b4a5c9b9c3aeefbd2aecd8cc4", // entropy 
                true, // prediction resistance 
                "b5b360eff76331f3", // nonce
                128, // security strength
                "50b4b4cd6857fc2ec152ccf668a481ed7ee41d87"); // result
        tv.setPersonalisationString("d4bb0210b271db81d6f04260daea7752");
        tv.setAdditionalInput("4dd26c87fb2c4fa68d1663226a51e3f8");  // additional input
        tv.setAdditionalInput("f9e8d2721334956f1549479916031947");  // additional input        
        rv.add(tv);  

        // line 823 of Hash_DRBG.txt
        tv = new TestVector(
                "8e898b45a75350dd7ae796d0e6b687f42d9e4ff91948f5e29d5d7c9b28735738", // entropy 
                false, // prediction resistance 
                "627c2efd05cefb2c", // nonce
                128, // security strength
                "538c9cde9432015281eeec13f4ce712624731b72"); // result
        tv.setMagicalReseed();
        rv.add(tv);  
        
        // line 837 of Hash_DRBG.txt
        tv = new TestVector(
                "2a5d2262d53cc928c5d45e028e2e049ea46a8f1b5fcf69229089e045649b9988", // entropy 
                false, // prediction resistance 
                "176e55882bd7cd42", // nonce
                128, // security strength
                "a1578253684465e65dae7872f1979edd5f961208"); // result
        tv.setMagicalReseed();
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
            EntropySource tes = new TestEntropySourceProvider(Hex.decode(tv.entropy()), tv.predictionResistance()).get(tv.securityStrength());
            byte[] nonce = Hex.decode(tv.nonce());
            byte[] personalisationString = Hex.decode(tv.personalisation());
            int securityStrength = tv.securityStrength();
            SP80090DRBG d = new HashSP800DRBG(digest, tes, nonce, personalisationString, securityStrength);
            
            byte[] output = new byte[20];
            
            d.generate(output, tv.additionalInput(0), tv.predictionResistance());
            String out = new String(Hex.encode(output));
            System.out.println(out);
            d.generate(output, tv.additionalInput(1), tv.reseed()  ? true : tv.predictionResistance());
            out = new String(Hex.encode(output));
            System.out.println(out);
            
            byte[] expected = Hex.decode(tv.expectedValue());
            
            ++c;
            if (!areEqual(expected, output)) 
            {
                System.out.println("Test #"+c+" failed");
                throw new Exception("Test Vector Failed, expected "+tv.expectedValue()+" got "+out);
            }
            System.out.println("Test Vector Passed, expected ; "+tv.expectedValue()+" got "+out);
        }
        System.out.println("Total tests completed = "+c+" of "+tests.size());
    }
}
