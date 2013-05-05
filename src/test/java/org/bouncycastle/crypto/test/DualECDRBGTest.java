package org.bouncycastle.crypto.test;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.DualECSP800DRBG;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.SP80090DRBG;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Dual EC SP800-90 DRBG
 */
public class DualECDRBGTest
    extends SimpleTest
{
    public String getName()
    {
        return "DualECDRBG";
    }

    public static void main(String[] args)
    {
        runTest(new DualECDRBGTest());
    }

    private TestVector[] createTestVectorData()
    {
        return new TestVector[]
            {
                new TestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    false,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "FF5163C388F791E96F1052D5C8F0BD6FBF7144839C4890FF85487C5C12702E4C9849AF518AE68DEB14D3A62702BBDE4B98AB211765FD87ACA12FC2A6",
                            "9A0A11F2DFB88F7260559DD8DA6134EB2B34CC0415FA8FD0474DB6B85E1A08385F41B435DF81296B1B4EDF66E0107C0844E3D28A89B05046B89177F2"
                        }),
                new TestVector(
                    new SHA256Digest(),
                    new SHA256EntropyProvider().get(128),
                    false,
                    "2021222324252627",
                    128,
                    new String[]
                        {
                            "C08E954FCD486D0B0934A0236692AC705A835D1A3C94D2ACD4684AB26E978D7D42E73CC06D6EC1472C63E51BED7F71518395836E2052BBD73A20CABB",
                            "1D76DEE36FCC5F9478C112EAFA1C4CCD0635435A6F3A247A3BA3849790B5245070E95C1A67BE7A39BFB213F2C0EFCC171A3253DA6D54DA4362EA2099"
                        })
                .addAdditionalInput("606162636465666768696A6B6C6D6E6F")
                .addAdditionalInput("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF")
            };
    }

    public void performTest()
        throws Exception
    {
        TestVector[] tests = createTestVectorData();

        for (int i = 0; i != tests.length; i++)
        {
            TestVector tv = tests[i];

            byte[] nonce = Hex.decode(tv.nonce());
            byte[] personalisationString = Hex.decode(tv.personalisation());

            SP80090DRBG d = new DualECSP800DRBG(tv.getDigest(), tv.entropySource(), nonce, personalisationString, tv.securityStrength());

            byte[] output = new byte[tv.expectedValue()[0].length() / 2];

            d.generate(output, tv.additionalInput(0), tv.predictionResistance());

            byte[] expected = Hex.decode(tv.expectedValue()[0]);

            if (!areEqual(expected, output))
            {
                fail("Test #" + (i + 1) + ".1 failed, expected " + tv.expectedValue()[0] + " got " + new String(Hex.encode(output)));
            }

            output = new byte[tv.expectedValue()[0].length() / 2];

            d.generate(output, tv.additionalInput(1), tv.predictionResistance());

            expected = Hex.decode(tv.expectedValue()[1]);
            if (!areEqual(expected, output))
            {
                fail("Test #" + (i + 1) + ".2 failed, expected " + tv.expectedValue()[1] + " got " + new String(Hex.encode(output)));
            }
        }
    }

    private class TestVector
    {
        private Digest _digest;
        private EntropySource _eSource;
        private boolean _pr;
        private String _nonce;
        private String _personalisation;
        private int _ss;
        private String[] _ev;
        private List _ai = new ArrayList();

        public TestVector(Digest digest, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
        {
            _digest = digest;
            _eSource = eSource;
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

        public TestVector addAdditionalInput(String input)
        {
            _ai.add(input);

            return this;
        }

        public TestVector setPersonalisationString(String p)
        {
            _personalisation = p;

            return this;
        }

        public EntropySource entropySource()
        {
            return _eSource;
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
            if (position >= len)
            {
                rv = null;
            }
            else
            {
                rv = Hex.decode((String)(_ai.get(position)));
            }
            return rv;
        }

    }

    private class SHA256EntropyProvider
        extends TestEntropySourceProvider
    {
        SHA256EntropyProvider()
        {
            super(Hex.decode(
                "000102030405060708090A0B0C0D0E0F " +
                    "808182838485868788898A8B8C8D8E8F" +
                    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"), true);
        }
    }
}
