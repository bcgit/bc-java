package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * SHA224 HMac Test
 */
public class SHA3HMacTest
    extends SimpleTest
{
    final static String[][] sha3_224 =
        {
            {
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
                "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c656e",
                "332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04"
            },
            {
                "00010203 04050607 08090a0b 0c0d0e0f" +
                    "10111213 14151617 18191a1b 1c1d1e1f" +
                    "20212223 24252627 28292a2b 2c2d2e2f" +
                    "30313233 34353637 38393a3b 3c3d3e3f" +
                    "40414243 44454647 48494a4b 4c4d4e4f" +
                    "50515253 54555657 58595a5b 5c5d5e5f" +
                    "60616263 64656667 68696a6b 6c6d6e6f" +
                    "70717273 74757677 78797a7b 7c7d7e7f" +
                    "80818283 84858687 88898a8b 8c8d8e8f",
                "53616d70 6c65206d 65737361 67652066" +
                    "6f72206b 65796c65 6e3d626c 6f636b6c" +
                    "656e",
                "d8b733bc f66c644a 12323d56 4e24dcf3" +
                    "fc75f231 f3b67968 359100c7"

            },
            {
                "00010203 04050607 08090a0b 0c0d0e0f" +
                    "10111213 14151617 18191a1b 1c1d1e1f" +
                    "20212223 24252627 28292a2b 2c2d2e2f" +
                    "30313233 34353637 38393a3b 3c3d3e3f" +
                    "40414243 44454647 48494a4b 4c4d4e4f" +
                    "50515253 54555657 58595a5b 5c5d5e5f" +
                    "60616263 64656667 68696a6b 6c6d6e6f" +
                    "70717273 74757677 78797a7b 7c7d7e7f" +
                    "80818283 84858687 88898a8b 8c8d8e8f" +
                    "90919293 94959697 98999a9b 9c9d9e9f" +
                    "a0a1a2a3 a4a5a6a7 a8a9aaab",
                "53616d70 6c65206d 65737361 67652066" +
                    "6f72206b 65796c65 6e3e626c 6f636b6c" +
                    "656e",
                "078695ee cc227c63 6ad31d06 3a15dd05" +
                    "a7e819a6 6ec6d8de 1e193e59"
            },
            {
                "00010203 04050607 08090a0b 0c0d0e0f" +
                    "10111213 14151617 18191a1b",
                "53616d70 6c65206d 65737361 67652066" +
                    "6f72206b 65796c65 6e3c626c 6f636b6c" +
                    "656e2c20 77697468 20747275 6e636174" +
                    "65642074 6167",
                "8569c54c bb00a9b7 8ff1b391 b0e5"
            },
            {
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "4869205468657265",
                "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7"
            }
        };

    final static String[][] sha3_256 =
        {
            {
                "00010203 04050607 08090a0b 0c0d0e0f" +
                    "10111213 14151617 18191a1b 1c1d1e1f",
                "53616d70 6c65206d 65737361 67652066" +
                    "6f72206b 65796c65 6e3c626c 6f636b6c" +
                    "656e",
                "4fe8e202 c4f058e8 dddc23d8 c34e4673" +
                    "43e23555 e24fc2f0 25d598f5 58f67205"
            },
            {
               "00010203 04050607 08090a0b 0c0d0e0f" +
                   "10111213 14151617 18191a1b 1c1d1e1f" +
                   "20212223 24252627 28292a2b 2c2d2e2f" +
                   "30313233 34353637 38393a3b 3c3d3e3f" +
                   "40414243 44454647 48494a4b 4c4d4e4f" +
                   "50515253 54555657 58595a5b 5c5d5e5f" +
                   "60616263 64656667 68696a6b 6c6d6e6f" +
                   "70717273 74757677 78797a7b 7c7d7e7f" +
                   "80818283 84858687",
                "53616d70 6c65206d 65737361 67652066" +
                    "6f72206b 65796c65 6e3d626c 6f636b6c" +
                    "656e",
                "68b94e2e 538a9be4 103bebb5 aa016d47" +
                    "961d4d1a a9060613 13b557f8 af2c3faa"
            },
            {
                "00010203 04050607 08090a0b 0c0d0e0f" +
                    "10111213 14151617 18191a1b 1c1d1e1f" +
                    "20212223 24252627 28292a2b 2c2d2e2f" +
                    "30313233 34353637 38393a3b 3c3d3e3f" +
                    "40414243 44454647 48494a4b 4c4d4e4f" +
                    "50515253 54555657 58595a5b 5c5d5e5f" +
                    "60616263 64656667 68696a6b 6c6d6e6f" +
                    "70717273 74757677 78797a7b 7c7d7e7f" +
                    "80818283 84858687 88898a8b 8c8d8e8f" +
                    "90919293 94959697 98999a9b 9c9d9e9f" +
                    "a0a1a2a3 a4a5a6a7",
                "53616d70 6c65206d 65737361 67652066" +
                    "6f72206b 65796c65 6e3e626c 6f636b6c" +
                    "656e",
                "9bcf2c23 8e235c3c e88404e8 13bd2f3a" +
                    "97185ac6 f238c63d 6229a00b 07974258"
            },
            {
                "00010203 04050607 08090a0b 0c0d0e0f" +
                    "10111213 14151617 18191a1b 1c1d1e1f",
                "53616d70 6c65206d 65737361 67652066" +
                    "6f72206b 65796c65 6e3c626c 6f636b6c" +
                    "656e2c20 77697468 20747275 6e636174" +
                    "65642074 6167",
                "c8dc7148 d8c1423a a549105d afdf9cad"
            },
            {
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "4869205468657265",
                "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"
            }
        };

    final static String[][] sha3_384 = {
        {
              "00010203 04050607 08090a0b 0c0d0e0f" +
                  "10111213 14151617 18191a1b 1c1d1e1f" +
                  "20212223 24252627 28292a2b 2c2d2e2f",
             "53616d70 6c65206d 65737361 67652066" +
                 "6f72206b 65796c65 6e3c626c 6f636b6c" +
                 "656e",
            "d588a3c5 1f3f2d90 6e8298c1 199aa8ff" +
                "62962181 27f6b38a 90b6afe2 c5617725" +
                "bc99987f 79b22a55 7b6520db 710b7f42"
        },
        {
            "00010203 04050607 08090a0b 0c0d0e0f" +
                "10111213 14151617 18191a1b 1c1d1e1f" +
                "20212223 24252627 28292a2b 2c2d2e2f" +
                "30313233 34353637 38393a3b 3c3d3e3f" +
                "40414243 44454647 48494a4b 4c4d4e4f" +
                "50515253 54555657 58595a5b 5c5d5e5f" +
                "60616263 64656667",
            "53616d70 6c65206d 65737361 67652066" +
                "6f72206b 65796c65 6e3d626c 6f636b6c" +
                "656e",
            "a27d24b5 92e8c8cb f6d4ce6f c5bf62d8" +
                "fc98bf2d 486640d9 eb8099e2 4047837f" +
                "5f3bffbe 92dcce90 b4ed5b1e 7e44fa90"
        },
        {
            "00010203 04050607 08090a0b 0c0d0e0f" +
                "10111213 14151617 18191a1b 1c1d1e1f" +
                "20212223 24252627 28292a2b 2c2d2e2f" +
                "30313233 34353637 38393a3b 3c3d3e3f" +
                "40414243 44454647 48494a4b 4c4d4e4f" +
                "50515253 54555657 58595a5b 5c5d5e5f" +
                "60616263 64656667 68696a6b 6c6d6e6f" +
                "70717273 74757677 78797a7b 7c7d7e7f" +
                "80818283 84858687 88898a8b 8c8d8e8f" +
                "90919293 94959697",
            "53616d70 6c65206d 65737361 67652066" +
                "6f72206b 65796c65 6e3e626c 6f636b6c" +
                "656e",
            "e5ae4c73 9f455279 368ebf36 d4f5354c" +
                "95aa184c 899d3870 e460ebc2 88ef1f94" +
                "70053f73 f7c6da2a 71bcaec3 8ce7d6ac"
        },
        {
            "00010203 04050607 08090a0b 0c0d0e0f" +
                "10111213 14151617 18191a1b 1c1d1e1f" +
                "20212223 24252627 28292a2b 2c2d2e2f",
            "53616d70 6c65206d 65737361 67652066" +
                "6f72206b 65796c65 6e3c626c 6f636b6c" +
                "656e2c20 77697468 20747275 6e636174" +
                "65642074 6167",
            "25f4bf53 606e91af 79d24a4b b1fd6aec" +
                "d44414a3 0c8ebb0a"
        },
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd"
        }
    };

    final static String[][] sha3_512 = {
        {
            "00010203 04050607 08090a0b 0c0d0e0f" +
                "10111213 14151617 18191a1b 1c1d1e1f" +
                "20212223 24252627 28292a2b 2c2d2e2f" +
                "30313233 34353637 38393a3b 3c3d3e3f",
            "53616d70 6c65206d 65737361 67652066" +
                "6f72206b 65796c65 6e3c626c 6f636b6c" +
                "656e",
            "4efd629d 6c71bf86 162658f2 9943b1c3" +
                "08ce27cd fa6db0d9 c3ce8176 3f9cbce5" +
                "f7ebe986 8031db1a 8f8eb7b6 b95e5c5e" +
                "3f657a89 96c86a2f 6527e307 f0213196"
        },
        {
            "00010203 04050607 08090a0b 0c0d0e0f" +
                "10111213 14151617 18191a1b 1c1d1e1f" +
                "20212223 24252627 28292a2b 2c2d2e2f" +
                "30313233 34353637 38393a3b 3c3d3e3f" +
                "40414243 44454647",
            "53616d70 6c65206d 65737361 67652066" +
                "6f72206b 65796c65 6e3d626c 6f636b6c" +
                "656e",
            "544e257e a2a3e5ea 19a590e6 a24b724c" +
                "e6327757 723fe275 1b75bf00 7d80f6b3" +
                "60744bf1 b7a88ea5 85f9765b 47911976" +
                "d3191cf8 3c039f5f fab0d29c c9d9b6da"
        },
        {
            "00010203 04050607 08090a0b 0c0d0e0f" +
                "10111213 14151617 18191a1b 1c1d1e1f" +
                "20212223 24252627 28292a2b 2c2d2e2f" +
                "30313233 34353637 38393a3b 3c3d3e3f" +
                "40414243 44454647 48494a4b 4c4d4e4f" +
                "50515253 54555657 58595a5b 5c5d5e5f" +
                "60616263 64656667 68696a6b 6c6d6e6f" +
                "70717273 74757677 78797a7b 7c7d7e7f" +
                "80818283 84858687",
            "53616d70 6c65206d 65737361 67652066" +
                "6f72206b 65796c65 6e3e626c 6f636b6c" +
                "656e",
            "5f464f5e 5b7848e3 885e49b2 c385f069" +
                "4985d0e3 8966242d c4a5fe3f ea4b37d4" +
                "6b65cece d5dcf594 38dd840b ab22269f" +
                "0ba7febd b9fcf746 02a35666 b2a32915"
        },
        {
            "00010203 04050607 08090a0b 0c0d0e0f" +
                "10111213 14151617 18191a1b 1c1d1e1f" +
                "20212223 24252627 28292a2b 2c2d2e2f" +
                "30313233 34353637 38393a3b 3c3d3e3f",
            "53616d70 6c65206d 65737361 67652066" +
                "6f72206b 65796c65 6e3c626c 6f636b6c" +
                "656e2c20 77697468 20747275 6e636174" +
                "65642074 6167",
            "7bb06d85 9257b25c e73ca700 df34c5cb" +
                "ef5c898b ac91029e 0b27975d 4e526a08"
        },
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"
        }
    };

    public String getName()
    {
        return "SHA3HMac";
    }

    public void performTest()
        throws Exception
    {
        doTest(new HMac(new SHA3Digest(224)), sha3_224);
        doTest(new HMac(new SHA3Digest(256)), sha3_256);
        doTest(new HMac(new SHA3Digest(384)), sha3_384);
        doTest(new HMac(new SHA3Digest(512)), sha3_512);
    }

    public void doTest(HMac hmac, String[][] data)
    {
        byte[] resBuf = new byte[hmac.getMacSize()];

        for (int i = 0; i < data.length; i++)
        {
            byte[] m = Hex.decode(data[i][1]);

            hmac.init(new KeyParameter(Hex.decode(data[i][0])));
            hmac.update(m, 0, m.length);
            hmac.doFinal(resBuf, 0);

            isTrue(hmac.getAlgorithmName() + " vector " + i + " failed got " + new String(Hex.encode(resBuf)), startsWith(resBuf, Hex.decode(data[i][2])));
        }

        //
        // test reset
        //
        int vector = 0; // vector used for test
        byte[] m = Hex.decode(data[vector][1]);

        hmac.init(new KeyParameter(Hex.decode(data[vector][0])));
        hmac.update(m, 0, m.length);
        hmac.doFinal(resBuf, 0);
        hmac.reset();
        hmac.update(m, 0, m.length);
        hmac.doFinal(resBuf, 0);

        isTrue(hmac.getAlgorithmName() + " reset with vector " + vector + " failed", Arrays.areEqual(resBuf, Hex.decode(data[vector][2])));
    }

    private static boolean startsWith(byte[] a, byte[] b)
    {
        if (a.length == b.length)
        {
            return Arrays.areEqual(a, b);
        }

        for (int i = 0; i != b.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static void main(
        String[]    args)
    {
        SHA3HMacTest test = new SHA3HMacTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
