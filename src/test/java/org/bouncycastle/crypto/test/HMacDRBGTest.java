package org.bouncycastle.crypto.test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.HMacSP800DRBG;
import org.bouncycastle.crypto.prng.SP80090DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HMAC SP800-90 DRBG
 */
public class HMacDRBGTest
    extends SimpleTest
{
    public String getName()
    {
        return "HMacDRBG";
    }

    public static void main(String[] args)
    {
        runTest(new HMacDRBGTest());
    }

    private class TestVector 
    {
        private Digest _digest;
        private EntropySource _eSource;
        private int _eBitLength;
        private boolean _pr;
        private String _nonce;
        private String _personalisation;
        private int _ss;
        private String[] _ev;
        private boolean _magicalReseed = false;
        private List _ai = new ArrayList();

        public TestVector(Digest digest, EntropySource eSource, int eBitLength, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _digest = digest;
            _eSource = eSource;
            _eBitLength = eBitLength;
            _pr = predictionResistance;
            _nonce = nonce;
            _ss = securityStrength;
            _ev = expected;
            _personalisation = "";
        }

        public Digest getDigest()
        {
            return _digest;
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

        public EntropySource entropySource()
        {
            return _eSource;
        }

        public int entropyBits()
        {
            return _eBitLength;
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

        TestVector tv;

        // line 7
        tv = new TestVector(
                new SHA1Digest(),
                new SHA1EntropySource(), 440,
                false,
                "2021222324",
                80,
                new String[]
                {
                    "5A7D3B449F481CB38DF79AD2B1FCC01E57F8135E8C0B22CD0630BFB0127FB5408C8EFC17A929896E",
                    "82cf772ec3e84b00fc74f5df104efbfb2428554e9ce367d03aeade37827fa8e9cb6a08196115d948"
                });

        rv.add(tv);

        tv = new TestVector(
            new SHA1Digest(),
            new SHA1EntropySource(), 440,
            true,
            "2021222324",
            80,
            new String[]
                {
                    "FEC4597F06A3A8CC8529D59557B9E661053809C0BC0EFC282ABD87605CC90CBA9B8633DCB1DAE02E",
                    "84ADD5E2D2041C01723A4DE4335B13EFDF16B0E51A0AD39BD15E862E644F31E4A2D7D843E57C5968"
                });

        rv.add(tv);

        tv = new TestVector(
                new SHA256Digest(),
                new SHA256EntropySource(), 440,
                false,
                "2021222324252627",
                128,
                new String[]
                {
                    "D67B8C1734F46FA3F763CF57C6F9F4F2" +
                    "DC1089BD8BC1F6F023950BFC5617635208C8501238AD7A44" +
                    "00DEFEE46C640B61AF77C2D1A3BFAA90EDE5D207406E5403",
                    "8FDAEC20F8B421407059E3588920DA7E" +
                    "DA9DCE3CF8274DFA1C59C108C1D0AA9B0FA38DA5C792037C" +
                    "4D33CD070CA7CD0C5608DBA8B885654639DE2187B74CB263"
                });

        rv.add(tv);

        tv = new TestVector(
            new SHA384Digest(),
            new SHA384EntropySource(), 888,
            false,
            "202122232425262728292A2B",
            192,
            new String[] {
                "03AB8BCE4D1DBBB636C5C5B7E1C58499FEB1C619CDD11D35" +
                "CD6CF6BB8F20EF27B6F5F9054FF900DB9EBF7BF30ED4DCBB" +
                "BC8D5B51C965EA226FFEE2CA5AB2EFD00754DC32F357BF7A" +
                "E42275E0F7704DC44E50A5220AD05AB698A22640AC634829",
                "B907E77144FD55A54E9BA1A6A0EED0AAC780020C41A15DD8" +
                "9A6C163830BA1D094E6A17100FF71EE30A96E1EE04D2A966" +
                "03832A4E404F1966C2B5F4CB61B9927E8D12AC1E1A24CF23" +
                "88C14E8EC96C35181EAEE32AAA46330DEAAFE5E7CE783C74" });

        tv.setPersonalisationString(
            "404142434445464748494A4B4C4D4E" +
            "4F505152535455565758595A5B5C5D5E5F60616263646566" +
            "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
            "7F808182838485868788898A8B8C8D8E8F90919293949596" +
            "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE");

        rv.add(tv);

        tv = new TestVector(
            new SHA512Digest(),
            new SHA512EntropySource(), 888,
            false,
            "202122232425262728292A2B2C2D2E2F",
            256,
            new String[] {
                "2A5FF6520C20F66E" +
                "D5EA431BD4AEAC58F975EEC9A015137D5C94B73AA09CB8B5" +
                "9D611DDEECEB34A52BB999424009EB9EAC5353F92A6699D2" +
                "0A02164EEBBC6492941E10426323898465DFD731C7E04730" +
                "60A5AA8973841FDF3446FB6E72A58DA8BDA2A57A36F3DD98" +
                "6DF85C8A5C6FF31CDE660BF8A841B21DD6AA9D3AC356B87B",
                "0EDC8D7D7CEEC7FE" +
                "36333FB30C0A9A4B27AA0BECBF075568B006C1C3693B1C29" +
                "0F84769C213F98EB5880909EDF068FDA6BFC43503987BBBD" +
                "4FC23AFBE982FE4B4B007910CC4874EEC217405421C8D8A1" +
                "BA87EC684D0AF9A6101D9DB787AE82C3A6A25ED478DF1B12" +
                "212CEC325466F3AC7C48A56166DD0B119C8673A1A9D54F67" });

        tv.setPersonalisationString(
            "404142434445464748494A4B4C4D4E" +
            "4F505152535455565758595A5B5C5D5E5F60616263646566" +
            "6768696A6B6C6D6E6F707172737475767778797A7B7C7D7E" +
            "7F808182838485868788898A8B8C8D8E8F90919293949596" +
            "9798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE");

        rv.add(tv);

        tv = new TestVector(
            new SHA512Digest(),
            new SHA512EntropySource(), 888,
            true,
            "202122232425262728292A2B2C2D2E2F",
            256,
            new String[]{
                "28FD6060C4F35F4D" +
                "317AB2060EE32019E0DAA330F3F5650BBCA57CB67EE6AF1C" +
                "6F25D1B01F3601EDA85DC2ED29A9B2BA4C85CF491CE7185F" +
                "1A2BD9378AE3C655BD1CEC2EE108AE7FC382989F6D4FEA8A" +
                "B01499697C2F07945CE02C5ED617D04287FEAF3BA638A4CE" +
                "F3BB6B827E40AF16279580FCF1FDAD830930F7FDE341E2AF",
                "C0B1601AFE39338B" +
                "58DC2BE7C256AEBE3C21C5A939BEEC7E97B3528AC420F0C6" +
                "341847187666E0FF578A8EB0A37809F877365A28DF2FA0F0" +
                "6354A6F02496747369375B9A9D6B756FDC4A8FB308E08256" +
                "9D79A85BB960F747256626389A3B45B0ABE7ECBC39D5CD7B" +
                "2C18DF2E5FDE8C9B8D43474C54B6F9839468445929B438C7"});

        rv.add(tv);

        return rv;
    }
        
    public void performTest() throws Exception
    {
        Collection<TestVector> tests = createTestVectorData();
        
        int c = 0;
        for (TestVector tv : tests)
        {
            byte[] nonce = Hex.decode(tv.nonce());
            byte[] personalisationString = Hex.decode(tv.personalisation());

            SP80090DRBG d = new HMacSP800DRBG(new HMac(tv.getDigest()), tv.entropySource(), tv.entropyBits(), nonce, personalisationString, tv.securityStrength());
            
            byte[] output = new byte[tv.expectedValue()[0].length() / 2];
            
            d.generate(output, tv.additionalInput(0), tv.predictionResistance());
            
            byte[] expected = Hex.decode(tv.expectedValue()[0]);

            String out = new String(Hex.encode(output));
            ++c;
            if (!areEqual(expected, output)) 
            {
                fail("Test #" + c + ".1 failed, expected " + tv.expectedValue()[0] + " got " + out);
            }

            output = new byte[tv.expectedValue()[0].length() / 2];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            expected = Hex.decode(tv.expectedValue()[1]);
            out = new String(Hex.encode(output));
            if (!areEqual(expected, output))
            {
                fail("Test #" + c + ".2 failed, expected " + tv.expectedValue()[1] + " got " + out);
            }
        }
    }

    private class SHA1EntropySource
        implements EntropySource
    {
        byte[] data = Hex.decode(
                   "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536"
                 + "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6"
                 + "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6");

        int index = 0;

        public boolean isPredictionResistant()
        {
            return false;
        }

        public byte[] getEntropy(int length)
        {
            byte[] rv = new byte[length];

            System.arraycopy(data, index, rv, 0, rv.length);

            index += length;

            return rv;
        }
    }

    private class SHA256EntropySource
        implements EntropySource
    {
        byte[] data = Hex.decode(
            "00010203040506" +
            "0708090A0B0C0D0E0F101112131415161718191A1B1C1D1E" +
            "1F202122232425262728292A2B2C2D2E2F30313233343536" +
            "80818283848586" +
            "8788898A8B8C8D8E8F909192939495969798999A9B9C9D9E" +
            "9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6" +
            "C0C1C2C3C4C5C6" +
            "C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDE" +
            "DFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6");

        int index = 0;

        public boolean isPredictionResistant()
        {
            return false;
        }

        public byte[] getEntropy(int length)
        {
            byte[] rv = new byte[length];

            System.arraycopy(data, index, rv, 0, rv.length);

            index += length;

            return rv;
        }
    }

    private class SHA384EntropySource
        implements EntropySource
    {
        byte[] data = Hex.decode(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223242526"
          + "2728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50515253545556"
          + "5758595A5B5C5D5E5F606162636465666768696A6B6C6D6E");

        int index = 0;

        public boolean isPredictionResistant()
        {
            return false;
        }

        public byte[] getEntropy(int length)
        {
            byte[] rv = new byte[length];

            System.arraycopy(data, index, rv, 0, rv.length);

            index += length;

            return rv;
        }
    }

    private class SHA512EntropySource
        implements EntropySource
    {
        byte[] data = Hex.decode(
            "000102030405060708090A0B0C0D0E"+
            "0F101112131415161718191A1B1C1D1E1F20212223242526"+
            "2728292A2B2C2D2E2F303132333435363738393A3B3C3D3E"+
            "3F404142434445464748494A4B4C4D4E4F50515253545556"+
            "5758595A5B5C5D5E5F606162636465666768696A6B6C6D6E"+
            "808182838485868788898A8B8C8D8E"+
            "8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6"+
            "A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBE"+
            "BFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6"+
            "D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEE"+
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCE"+
            "CFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6"+
            "E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE"+
            "FF000102030405060708090A0B0C0D0E0F10111213141516"+
            "1718191A1B1C1D1E1F202122232425262728292A2B2C2D2E");

        int index = 0;

        public boolean isPredictionResistant()
        {
            return false;
        }

        public byte[] getEntropy(int length)
        {
            byte[] rv = new byte[length];

            System.arraycopy(data, index, rv, 0, rv.length);

            index += length;

            return rv;
        }
    }
}
