package org.bouncycastle.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.Blake2spDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Blake2spDigestTest
    extends TestCase
{

    private static final String[][] nonKeyedTestVectors = {
            {

                    "",
                    "",
                    "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
            },
            {

                    "00",
                    "",
                    "a6b9eecc25227ad788c99d3f236debc8da408849e9a5178978727a81457f7239"
            },
            {

                    "0001",
                    "",
                    "dacadece7a8e6bf3abfe324ca695436984b8195d29f6bbd896e41e18e21c9145"
            },
            {

                    "000102",
                    "",
                    "ed14413b40da689f1f7fed2b08dff45b8092db5ec2c3610e02724d202f423c46"
            },
            {

                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafb",
                    "",
                    "251d8d09fc48dd1d6af8ffdf395091a46e05b8b7c5ec0c79b68a8904c827bdea"
            },
            {

                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfc",
                    "",
                    "c2d14d69fd0bbd1c0fe8c845d5fd6a8f740151b1d8eb4d26364bb02dae0c13bc"
            },
            {

                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd",
                    "",
                    "2e5fe21f8f1b6397a38a603d60b6f53c3b5db20aa56c6d44bebd4828ce28f90f"
            },
            {

                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
                    "",
                    "25059f10605e67adfe681350666e15ae976a5a571c13cf5bc8053f430e120a52"
            },
    };
    private static final String[][] keyedTestVectors = {
            // input/message, key, hash
            {
                    "",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "715cb13895aeb678f6124160bff21465b30f4f6874193fc851b4621043f09cc6"
            },
            {
                    "00",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "40578ffa52bf51ae1866f4284d3a157fc1bcd36ac13cbdcb0377e4d0cd0b6603"
            },
            {
                    "0001",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "67e3097545bad7e852d74d4eb548eca7c219c202a7d088db0efeac0eac304249"
            },
            {
                    "000102",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "8dbcc0589a3d17296a7a58e2f1eff0e2aa4210b58d1f88b86d7ba5f29dd3b583"
            },
            {
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafb",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "e15f368b4406c1f65557c8355cbe694b633e26f155f52b7da94cfb23fd4a5d96"
            },
            {
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfc",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "437ab2d74f50ca86cc3de9be70e4554825e33d824b3a492362e2e9d611bc579d"
            },
            {
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "2b9158c722898e526d2cdd3fc088e9ffa79a9b73b7d2d24bc478e21cdb3b6763"
            },
            {
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "0c8a36597d7461c63a94732821c941856c668376606c86a52de0ee4104c615db"
            }
    };

    public void testDigestWithKeyedTestVectors()
    {
        Blake2spDigest digest = new Blake2spDigest(Hex.decode(
                keyedTestVectors[0][1]));
        for (int i = 0; i != keyedTestVectors.length; i++)
        {
            String[] keyedTestVector = keyedTestVectors[i];
            byte[] input = Hex.decode(keyedTestVector[0]);
            digest.reset();

            digest.update(input, 0, input.length);
            byte[] hash = new byte[32];
            digest.doFinal(hash, 0);

            if (!Arrays.areEqual(Hex.decode(keyedTestVector[2]), hash))
            {
                assertEquals("BLAKE2s mismatch on test vector: ", keyedTestVector[2], Hex.toHexString(hash));
            }
        }
    }
    public void testDigestWithNonKeyedTestVectors()
    {
        Blake2spDigest digest = new Blake2spDigest(Hex.decode(
                nonKeyedTestVectors[0][1]));
        for (int i = 0; i != nonKeyedTestVectors.length; i++)
        {
            String[] keyedTestVector = nonKeyedTestVectors[i];
            byte[] input = Hex.decode(keyedTestVector[0]);
            digest.reset();

            digest.update(input, 0, input.length);
            byte[] hash = new byte[32];
            digest.doFinal(hash, 0);

            if (!Arrays.areEqual(Hex.decode(keyedTestVector[2]), hash))
            {
                assertEquals("BLAKE2s mismatch on test vector: ", keyedTestVector[2], Hex.toHexString(hash));
            }
        }
    }
    public void testMyTest() throws Exception
    {
        byte[] key = new byte[32];
        byte[] buf = new byte[256];
        byte[][] stepOne = new byte[256][32];

        for (int i = 0; i < 32; i++)
        {
            key[i] = (byte) i;
        }
        for (int i = 0; i < 256; i++)
        {
            buf[i] = (byte) i;
        }
//        System.out.println("key: " + Hex.toHexString(key));
//        System.out.println("buf: " + Hex.toHexString(buf));

        Blake2spDigest digest = new Blake2spDigest(key);
        for (int step = 1; step < 64; step++)
        {
            for (int i = 0; i < 256; i++)
            {
//                Blake2spDigest digest = new Blake2spDigest(key);
                int mlen = i;
                int pOffset = 0;
                byte[] hash = new byte[32];

                while(mlen >= step)
                {
                    digest.update(buf, pOffset, step);
                    mlen -= step;
                    pOffset += step;
                }

                digest.update(buf, pOffset, mlen);

                digest.doFinal(hash, 0);
                if(step == 1)
                {
                    System.arraycopy(hash, 0, stepOne[i], 0, hash.length);
                }
                else
                {
                    assertTrue("BLAKE2s mismatch on test vector: ", Arrays.areEqual(stepOne[i], hash));
                }

            }
        }
    }
}
