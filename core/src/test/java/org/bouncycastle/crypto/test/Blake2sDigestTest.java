package org.bouncycastle.crypto.test;

import java.util.Random;

import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Blake2sDigestTest
    extends SimpleTest
{

    // Vectors from BLAKE2 web site: https://blake2.net/blake2s-test.txt
    private static final String[][] keyedTestVectors = {
        // input/message, key, hash
        {
            "",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
        },
        {
            "00",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
        },
        {
            "0001",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803",
        },
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "172ffc67153d12e0ca76a8b6cd5d4731885b39ce0cac93a8972a18006c8b8baf",
        },
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "4f8ce1e51d2fe7f24043a904d898ebfc91975418753413aa099b795ecb35cedb",
        },
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd",
        },
    };

    public String getName()
    {
        return "BLAKE2s";
    }

    public void testDigestWithKeyedTestVectors()
    {
        Blake2sDigest digest = new Blake2sDigest(Hex.decode(
            keyedTestVectors[0][1]));
        for (int i = 0; i != keyedTestVectors.length; i++)
        {
            String[] keyedTestVector = keyedTestVectors[i];
            byte[] input = Hex.decode(keyedTestVector[0]);
            digest.reset();

            digest.update(input, 0, input.length);
            byte[] hash = new byte[32];
            digest.doFinal(hash, 0);

            if (!areEqual(Hex.decode(keyedTestVector[2]), hash))
            {
                fail("BLAKE2s mismatch on test vector ",
                    keyedTestVector[2],
                    new String(Hex.encode(hash)));
            }
        }
    }

    public void testDigestWithKeyedTestVectorsAndRandomUpdate()
    {
        Blake2sDigest digest = new Blake2sDigest(Hex.decode(
            keyedTestVectors[0][1]));
        Random random = new Random();
        for (int i = 0; i < 100; i++)
        {
            for (int j = 0; j != keyedTestVectors.length; j++)
            {
                String[] keyedTestVector = keyedTestVectors[j];
                byte[] input = Hex.decode(keyedTestVector[0]);
                if (input.length < 3)
                {
                    continue;
                }
                digest.reset();

                int pos = (random.nextInt() & 0xffff) % input.length;
                if (pos > 0)
                {
                    digest.update(input, 0, pos);
                }
                digest.update(input[pos]);
                if (pos < (input.length - 1))
                {
                    digest.update(input, pos + 1, input.length - (pos + 1));
                }

                byte[] hash = new byte[32];
                digest.doFinal(hash, 0);

                if (!areEqual(Hex.decode(keyedTestVector[2]), hash))
                {
                    fail("BLAKE2s mismatch on test vector ",
                        keyedTestVector[2],
                        new String(Hex.encode(hash)));
                }
            }
        }
    }

    private void testLengthConstruction()
    {
        try
        {
            new Blake2sDigest(-1);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256", e.getMessage());
        }

        try
        {
            new Blake2sDigest(9);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256", e.getMessage());
        }
        
        try
        {
            new Blake2sDigest(512);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256", e.getMessage());
        }

        try
        {
            new Blake2sDigest(null, -1, null, null);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Invalid digest length (required: 1 - 32)", e.getMessage());
        }

        try
        {
            new Blake2sDigest(null, 33, null, null);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Invalid digest length (required: 1 - 32)", e.getMessage());
        }
    }

    private void testNullKeyVsUnkeyed()
    {
        byte[] abc = Strings.toByteArray("abc");

        for (int i = 1; i != 32; i++)
        {
            Blake2sDigest dig1 = new Blake2sDigest(i * 8);
            Blake2sDigest dig2 = new Blake2sDigest(null, i, null, null);

            byte[] out1 = new byte[i];
            byte[] out2 = new byte[i];

            dig1.update(abc, 0, abc.length);
            dig2.update(abc, 0, abc.length);

            dig1.doFinal(out1, 0);
            dig2.doFinal(out2, 0);

            isTrue(Arrays.areEqual(out1, out2));
        }
    }

    public void testReset()
    {
        // Generate a non-zero key
        byte[] key = new byte[32];
        for (byte i = 0; i < key.length; i++)
        {
            key[i] = i;
        }
        // Generate some non-zero input longer than the key
        byte[] input = new byte[key.length + 1];
        for (byte i = 0; i < input.length; i++)
        {
            input[i] = i;
        }
        // Hash the input
        Blake2sDigest digest = new Blake2sDigest(key);
        digest.update(input, 0, input.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        // Create a second instance, hash the input without calling doFinal()
        Blake2sDigest digest1 = new Blake2sDigest(key);
        digest1.update(input, 0, input.length);
        // Reset the second instance and hash the input again
        digest1.reset();
        digest1.update(input, 0, input.length);
        byte[] hash1 = new byte[digest.getDigestSize()];
        digest1.doFinal(hash1, 0);
        // The hashes should be identical
        if (!areEqual(hash, hash1))
        {
            fail("BLAKE2s mismatch on test vector ",
                new String(Hex.encode(hash)),
                new String(Hex.encode(hash1)));
        }
    }

    // Self-test routine from https://tools.ietf.org/html/rfc7693#appendix-E
    private static final String SELF_TEST_RESULT =
        "6A411F08CE25ADCDFB02ABA641451CEC53C598B24F4FC787FBDC88797F4C1DFE";
    private static final int[] SELF_TEST_DIGEST_LEN = {16, 20, 28, 32};
    private static final int[] SELF_TEST_INPUT_LEN = {0, 3, 64, 65, 255, 1024};

    private static byte[] selfTestSequence(int len, int seed)
    {
        int a = 0xDEAD4BAD * seed;
        int b = 1;
        int t;
        byte[] out = new byte[len];

        for (int i = 0; i < len; i++)
        {
            t = a + b;
            a = b;
            b = t;
            out[i] = (byte)((t >> 24) & 0xFF);
        }

        return out;
    }

    public void runSelfTest()
    {
        Blake2sDigest testDigest = new Blake2sDigest();
        byte[] md = new byte[32];

        for (int i = 0; i < 4; i++)
        {
            int outlen = SELF_TEST_DIGEST_LEN[i];
            for (int j = 0; j < 6; j++)
            {
                int inlen = SELF_TEST_INPUT_LEN[j];

                // unkeyed hash
                byte[] in = selfTestSequence(inlen, inlen);
                Blake2sDigest unkeyedDigest = new Blake2sDigest(outlen * 8);
                unkeyedDigest.update(in, 0, inlen);
                unkeyedDigest.doFinal(md, 0);
                // hash the hash
                testDigest.update(md, 0, outlen);

                // keyed hash
                byte[] key = selfTestSequence(outlen, outlen);
                Blake2sDigest keyedDigest = new Blake2sDigest(key, outlen, null,
                    null);
                keyedDigest.update(in, 0, inlen);
                keyedDigest.doFinal(md, 0);
                // hash the hash
                testDigest.update(md, 0, outlen);
            }
        }

        byte[] hash = new byte[32];
        testDigest.doFinal(hash, 0);
        if (!areEqual(Hex.decode(SELF_TEST_RESULT), hash))
        {
            fail("BLAKE2s mismatch on test vector ",
                SELF_TEST_RESULT,
                new String(Hex.encode(hash)));
        }
    }

    public void performTest()
        throws Exception
    {
        testDigestWithKeyedTestVectors();
        testDigestWithKeyedTestVectorsAndRandomUpdate();
        testReset();
        runSelfTest();
        testNullKeyVsUnkeyed();
        testLengthConstruction();
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new Blake2sDigestTest());
    }
}
