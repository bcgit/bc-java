package org.bouncycastle.crypto.random.test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.random.SP800SecureRandomBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class SP800RandomTest
    extends SimpleTest
{

    public String getName()
    {
        return "SP800RandomTest";
    }

    private void testDigestRandom()
    {
        SP800SecureRandomBuilder rBuild = new SP800SecureRandomBuilder();

        TestVector tv = new TestVector("a37a3e08d8393feb01c4d78cb6a4d1e210c288c89e9838176bc78946745f1c5bea44cf15e061601bfd45f7b3b95be924", true, "8243299805c0877e", 128, "a05002f98d5676e1b2e3b3d4686bb9055a830a39");

        rBuild.setNonce(tv.nonce());
        rBuild.setPersonalizationString(tv.personalisation());
        rBuild.setSecurityStrength(tv.securityStrength());
        rBuild.setEntropySource(new FixedSecureRandom(tv.entropy()), true);
        rBuild.setSeedLength(440);

        SecureRandom random = rBuild.build(new SHA1Digest(), true);

        byte[] expected = tv.expectedValue();
        byte[] produced = new byte[expected.length];

        random.nextBytes(produced);

        random.nextBytes(produced);

        if (!Arrays.areEqual(expected, produced))
        {
            fail("SP800 digest SecureRandom produced incorrect result");
        }
    }

    private void testCTRRandom()
    {
        SP800SecureRandomBuilder rBuild = new SP800SecureRandomBuilder();

        TestVector tv = new TestVector("a37a3e08d8393feb01c4d78cb6a4d1e210c288c89e9838176bc78946745f1c5bea44cf15e061601bfd45f7b3b95be924", true, "8243299805c0877e", 128, "a05002f98d5676e1b2e3b3d4686bb9055a830a39");

        rBuild.setNonce(tv.nonce());
        rBuild.setPersonalizationString(tv.personalisation());
        rBuild.setSecurityStrength(tv.securityStrength());
        rBuild.setEntropySource(new FixedSecureRandom(tv.entropy()), true);
        rBuild.setSeedLength(440);

        SecureRandom random = rBuild.build(new AESFastEngine(), 192, true);

        byte[] expected = tv.expectedValue();
        byte[] produced = new byte[expected.length];

        random.nextBytes(produced);

        random.nextBytes(produced);

        // TODO:
//        if (!Arrays.areEqual(expected, produced))
//        {
//            fail("SP800 CTR SecureRandom produced incorrect result");
//        }
    }

    public void performTest()
        throws Exception
    {
        testDigestRandom();
        testCTRRandom();
    }

    public static void main(String[] args)
    {
        runTest(new SP800RandomTest());
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

        public byte[] entropy()
        {
            return Hex.decode(_entropy);
        }

        public boolean predictionResistance()
        {
            return _pr;
        }

        public byte[] nonce()
        {
            return Hex.decode(_nonce);
        }

        public byte[] personalisation()
        {
            return Hex.decode(_personalisation);
        }

        public int securityStrength()
        {
            return _ss;
        }

        public byte[] expectedValue()
        {
            return Hex.decode(_ev);
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

}
