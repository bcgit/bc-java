package org.bouncycastle.gpg.test;

import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.gpg.KeyGripCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

public class KeyGripCalculatorTest
    extends SimpleTest
{
    public String getName()
    {
        return "KeyGripCalculator";
    }

    public void performTest()
        throws Exception
    {
        rsaKeygripMatchesSha1OfModulus();
        wrongAlgorithmRejected();
        unsupportedKeyTypeRejected();
    }

    private void rsaKeygripMatchesSha1OfModulus()
        throws Exception
    {
        BigInteger n = new BigInteger(
            "C8E25F2BD8B6E0E0AAB2C0E80E27F49D5BD55B9C30B6F7AAD9E2A3F31B5BFD5D" +
            "1F0B2C5C9C9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBA9F9E9D9C9B9A99989796959" +
            "493929190", 16);
        BigInteger e = BigInteger.valueOf(65537);

        RSAPublicBCPGKey key = new RSAPublicBCPGKey(n, e);

        byte[] grip = new KeyGripCalculator(sha1()).calculateKeygrip(key);

        // Reference: SHA-1 over the unsigned big-endian encoding of n
        // (matches libgcrypt cipher/rsa.c::compute_keygrip).
        SHA1Digest md = new SHA1Digest();
        byte[] nBytes = BigIntegers.asUnsignedByteArray(n);
        md.update(nBytes, 0, nBytes.length);
        byte[] expected = new byte[md.getDigestSize()];
        md.doFinal(expected, 0);

        if (!Arrays.areEqual(expected, grip))
        {
            fail("RSA keygrip did not match SHA-1 of modulus");
        }
        if (grip.length != 20)
        {
            fail("keygrip length wrong");
        }
    }

    private void wrongAlgorithmRejected()
    {
        try
        {
            new KeyGripCalculator(sha256());
            fail("expected IllegalArgumentException for non-SHA1 digest calculator");
        }
        catch (IllegalArgumentException expected)
        {
            // expected
        }
    }

    private void unsupportedKeyTypeRejected()
        throws Exception
    {
        BCPGKey unsupported = new BCPGKey()
        {
            public String getFormat()
            {
                return "PGP";
            }

            public byte[] getEncoded()
            {
                return new byte[0];
            }
        };

        try
        {
            new KeyGripCalculator(sha1()).calculateKeygrip(unsupported);
            fail("expected IllegalArgumentException for unsupported key type");
        }
        catch (IllegalArgumentException expected)
        {
            // expected
        }
    }

    private static PGPDigestCalculator sha1()
    {
        return new SimpleDigestCalculator(HashAlgorithmTags.SHA1, new SHA1Digest());
    }

    private static PGPDigestCalculator sha256()
    {
        return new SimpleDigestCalculator(HashAlgorithmTags.SHA256, new SHA256Digest());
    }

    private static class SimpleDigestCalculator
        implements PGPDigestCalculator
    {
        private final int algorithm;
        private final org.bouncycastle.crypto.Digest digest;
        private final OutputStream stream;

        SimpleDigestCalculator(int algorithm, final org.bouncycastle.crypto.Digest digest)
        {
            this.algorithm = algorithm;
            this.digest = digest;
            this.stream = new OutputStream()
            {
                public void write(int b)
                {
                    digest.update((byte)b);
                }

                public void write(byte[] buf, int off, int len)
                {
                    digest.update(buf, off, len);
                }
            };
        }

        public int getAlgorithm()
        {
            return algorithm;
        }

        public OutputStream getOutputStream()
        {
            return stream;
        }

        public byte[] getDigest()
        {
            byte[] out = new byte[digest.getDigestSize()];
            digest.doFinal(out, 0);
            return out;
        }

        public void reset()
        {
            digest.reset();
        }
    }

    public static void main(String[] args)
    {
        runTest(new KeyGripCalculatorTest());
    }
}
