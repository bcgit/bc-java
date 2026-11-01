package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class Blake2bDigestTest
    extends SimpleTest
{

    private static final String[][] keyedTestVectors =
        { // input/message, key, hash

            // Vectors from BLAKE2 web site: https://blake2.net/blake2b-test.txt
            {
                "",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"},

            {
                "00",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd"},

            {
                "0001",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965"},

            {
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "f1aa2b044f8f0c638a3f362e677b5d891d6fd2ab0765f6ee1e4987de057ead357883d9b405b9d609eea1b869d97fb16d9b51017c553f3b93c0a1e0f1296fedcd"},

            {
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "c230f0802679cb33822ef8b3b21bf7a9a28942092901d7dac3760300831026cf354c9232df3e084d9903130c601f63c1f4a4a4b8106e468cd443bbe5a734f45f"},

            {
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"}};

    private final static String[][] unkeyedTestVectors =
        { // from: https://fossies.org/linux/john/src/rawBLAKE2_512_fmt_plug.c
            // hash, input/message
            // digests without leading $BLAKE2$
            {
                "4245af08b46fbb290222ab8a68613621d92ce78577152d712467742417ebc1153668f1c9e1ec1e152a32a9c242dc686d175e087906377f0c483c5be2cb68953e",
                "blake2"},
            {
                "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0",
                "hello world"},
            {
                "1f7d9b7c9a90f7bfc66e52b69f3b6c3befbd6aee11aac860e99347a495526f30c9e51f6b0db01c24825092a09dd1a15740f0ade8def87e60c15da487571bcef7",
                "verystrongandlongpassword"},
            {
                "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
                "The quick brown fox jumps over the lazy dog"},
            {
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                ""},
            {
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                "abc"},
        };

    public String getName()
    {
        return "BLAKE2b";
    }

    private void offsetTest(
        Digest digest,
        byte[] input,
        byte[] expected)
    {
        byte[] resBuf = new byte[expected.length + 11];

        digest.update(input, 0, input.length);

        digest.doFinal(resBuf, 11);

        if (!areEqual(Arrays.copyOfRange(resBuf, 11, resBuf.length), expected))
        {
            fail("Offset failed got " + new String(Hex.encode(resBuf)));
        }
    }

    // fanout, depth, leaf length, node offset, node depth, inner length: expected from Python's hashlib.blake2b
    private static final long[][] parameterBlocks =
        {
            { 2, 2, 4096L, 0L, 0, 0 },
            { 2, 2, 0xff000001L, 0L, 0, 0 },
            { 2, 200, 1L, 0L, 0, 0 },
            { 200, 3, 0L, 7L, 2, 32 },
            { 2, 2, 0L, (1L << 44) - 1, 1, 64 },
            { 2, 2, 0L, 1L << 32, 0, 0 },
            { 1, 1, 0x01010020L, 0L, 0, 0 },
        };

    private static final String[] parameterBlockHashes =
        {
            "6f7b06e531f3349bce0e60198e446535b8e784412ff29c0ed301c49987dac149",
            "f37435dc697b6de279f70e924a3861e088ee106c7f0e974e09c5708bd103356d",
            "fb1ed091bcb7f4ef17eb242bf096b25c82d33b7fdb721c691b4435baaea3a4ca",
            "6e81ec04eb9d9e4ea6718c6c449b86ba6fd303ead49c2be5e89d11da1772a0a2",
            "ae5305efa4e8911b504ee0c09b4120ad67f4f64b365d549103c68174540ded76",
            "5fcc7557293f3fd8357128d2af37d6f94e64234ea14ee0f6124d73aa6ba02c83",
            "168a54880f64e9fa7cda21ae41f58f1fa2d21766286ea36e050c0c3e06ae80df",
        };

    private static class LastNodeDigest
        extends Blake2bDigest
    {
        LastNodeDigest(byte[] param)
        {
            super(null, param);
            setAsLastNode();
        }
    }

    private static byte[] parameterBlock(long[] fields)
    {
        byte[] param = new byte[64];
        param[0] = 32;
        param[2] = (byte)fields[0];
        param[3] = (byte)fields[1];
        Pack.intToLittleEndian((int)fields[2], param, 4);
        Pack.longToLittleEndian(fields[3], param, 8);
        param[16] = (byte)fields[4];
        param[17] = (byte)fields[5];
        return param;
    }

    private void checkHash(String label, String expected, Blake2bDigest digest, byte[] message, int off)
    {
        digest.update(message, off, message.length - off);
        byte[] hash = new byte[32];
        digest.doFinal(hash, 0);
        if (!Arrays.areEqual(Hex.decode(expected), hash))
        {
            fail(label, expected, new String(Hex.encode(hash)));
        }
    }

    private void parameterBlockTest()
    {
        byte[] message = new byte[100];
        for (int i = 0; i != message.length; i++)
        {
            message[i] = (byte)i;
        }

        for (int i = 0; i != parameterBlocks.length; i++)
        {
            byte[] param = parameterBlock(parameterBlocks[i]);
            String expected = parameterBlockHashes[i];

            Blake2bDigest digest = new Blake2bDigest(null, param);
            checkHash("parameter block " + i, expected, digest, message, 0);
            checkHash("parameter block after reset " + i, expected, digest, message, 0);

            digest.update(message, 0, 40);
            Blake2bDigest copy = new Blake2bDigest(digest);
            checkHash("copy of parameter block " + i, expected, copy, message, 40);
            checkHash("copy of parameter block after reset " + i, expected, copy, message, 0);
        }

        // hashlib.blake2b(message, digest_size=32, fanout=2, depth=2, leaf_size=4096, last_node=True)
        String lastNode = "ee84d71e587104bea56b37f12375c4e967d99470f014dafac39d724729b4ad7d";
        Blake2bDigest lastNodeDigest = new LastNodeDigest(parameterBlock(parameterBlocks[0]));
        checkHash("last node", lastNode, lastNodeDigest, message, 0);
        checkHash("last node after reset", lastNode, lastNodeDigest, message, 0);
        Blake2bDigest lastNodeCopy = new Blake2bDigest(new LastNodeDigest(parameterBlock(parameterBlocks[0])));
        checkHash("copy of last node", lastNode, lastNodeCopy, message, 0);
        checkHash("copy of last node after reset", lastNode, lastNodeCopy, message, 0);
    }

    private static byte[] keyedParameterBlock(int keyLength, byte saltByte, byte personalByte)
    {
        byte[] param = new byte[64];
        param[0] = 32;
        param[1] = (byte)keyLength;
        param[2] = 1;
        param[3] = 1;
        param[32] = saltByte;
        param[48] = personalByte;
        return param;
    }

    /**
     * The key, salt and personalization given with an explicit parameter block have to be used - reference values
     * from Python's hashlib.blake2b(message, digest_size=32, key=..., salt=..., person=...).
     */
    private void parameterBlockKeyTest()
    {
        byte[] message = Strings.toByteArray("pay 100 to alice");
        byte[] key = new byte[32];
        for (int i = 0; i != key.length; i++)
        {
            key[i] = (byte)i;
        }
        byte[] otherKey = new byte[32];
        otherKey[0] = 99;

        // key=bytes(range(32))
        String keyed = "506198205a70e42a24454fdb42560289f373003fc2c595dbb174b6ce15649142";
        // salt=b'\x01' + bytes(15), person=b'\x02' + bytes(15)
        String salted = "7b78cadbd5fc717c47dd9100fee2fa3331b402bf6f73d3325ab0c22cc74561ab";
        // both of the above
        String keyedSalted = "89bc924b32fb8ad0b6dce0f7ddf76dc7f32c856728ebe0c4056f918db9ad9b02";

        Blake2bDigest digest = new Blake2bDigest(key, keyedParameterBlock(32, (byte)0, (byte)0));
        checkHash("keyed parameter block", keyed, digest, message, 0);
        checkHash("keyed parameter block after reset", keyed, digest, message, 0);
        digest.update(message, 0, 5);
        checkHash("copy of keyed parameter block", keyed, new Blake2bDigest(digest), message, 5);

        checkHash("salted parameter block", salted, new Blake2bDigest(null, keyedParameterBlock(0, (byte)1, (byte)2)), message, 0);
        checkHash("keyed and salted parameter block", keyedSalted, new Blake2bDigest(key, keyedParameterBlock(32, (byte)1, (byte)2)), message, 0);

        byte[] tag = new byte[32];
        byte[] otherTag = new byte[32];
        digest = new Blake2bDigest(key, keyedParameterBlock(32, (byte)0, (byte)0));
        digest.update(message, 0, message.length);
        digest.doFinal(tag, 0);
        digest = new Blake2bDigest(otherKey, keyedParameterBlock(32, (byte)0, (byte)0));
        digest.update(message, 0, message.length);
        digest.doFinal(otherTag, 0);
        isTrue("different keys gave the same tag", !Arrays.areEqual(tag, otherTag));

        // a null key leaves the key to the caller, as BLAKE2bp does, and so does not give the keyed tag
        digest = new Blake2bDigest(null, keyedParameterBlock(32, (byte)0, (byte)0));
        digest.update(message, 0, message.length);
        digest.doFinal(otherTag, 0);
        isTrue("a null key gave the keyed tag", !Arrays.areEqual(tag, otherTag));

        try
        {
            new Blake2bDigest(key, keyedParameterBlock(0, (byte)0, (byte)0));
            fail("key accepted with a key length of 0 in the parameter block");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("key length does not match parameter block", e.getMessage());
        }

        try
        {
            new Blake2bDigest(null, new byte[18]);
            fail("short parameter block accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("BLAKE2b parameter block must be 64 bytes", e.getMessage());
        }
    }

    /**
     * An empty key is no key, as in hashlib.blake2b(message, key=b''), not a block of zeros.
     */
    private void emptyKeyTest()
    {
        byte[] message = Strings.toByteArray("pay 100 to alice");

        // hashlib.blake2b(message, digest_size=32, key=b'')
        String unkeyed256 = "f5689c1f157ad1211337d7f631d209c5dc483b5f06396f7bb80e4a1482da1f0c";
        Blake2bDigest digest = new Blake2bDigest(new byte[0], 32, null, null);
        checkHash("empty key", unkeyed256, digest, message, 0);
        checkHash("empty key after reset", unkeyed256, digest, message, 0);

        // hashlib.blake2b(message, key=b'')
        byte[] expected = Hex.decode("a1da4c14c2c9766c77b0240cf792324fd1009e069f154836b09db59b21f7444e7b347a3c855e86516c5a127ed60242f18c8c112e55449cfd5315814bc5d12db7");
        digest = new Blake2bDigest(new byte[0]);
        for (int i = 0; i != 2; i++)
        {
            digest.update(message, 0, message.length);
            byte[] hash = new byte[64];
            digest.doFinal(hash, 0);
            isTrue("empty prefix-MAC key " + i, Arrays.areEqual(expected, hash));
        }
    }

    public void performTest()
        throws Exception
    {
        parameterBlockTest();
        parameterBlockKeyTest();
        emptyKeyTest();

        // test keyed test vectors:

        Blake2bDigest blake2bkeyed = new Blake2bDigest(Hex.decode(keyedTestVectors[0][1]));
        for (int tv = 0; tv < keyedTestVectors.length; tv++)
        {

            byte[] input = Hex.decode(keyedTestVectors[tv][0]);
            blake2bkeyed.reset();

            blake2bkeyed.update(input, 0, input.length);
            byte[] keyedHash = new byte[64];
            blake2bkeyed.doFinal(keyedHash, 0);

            if (!Arrays.areEqual(Hex.decode(keyedTestVectors[tv][2]), keyedHash))
            {
                fail("BLAKE2b mismatch on test vector ",
                    keyedTestVectors[tv][2],
                    new String(Hex.encode(keyedHash)));
            }

            offsetTest(blake2bkeyed, input, keyedHash);
        }

        Blake2bDigest blake2bunkeyed = new Blake2bDigest();
        // test unkeyed test vectors:
        for (int i = 0; i < unkeyedTestVectors.length; i++)
        {

            // blake2bunkeyed.update(
            // unkeyedTestVectors[i][1].getBytes("UTF-8"));
            // test update(byte b)
            byte[] unkeyedInput = Strings.toUTF8ByteArray(unkeyedTestVectors[i][1]);
            for (int j = 0; j < unkeyedInput.length; j++)
            {
                blake2bunkeyed.update(unkeyedInput[j]);
            }

            byte[] unkeyedHash = new byte[64];
            blake2bunkeyed.doFinal(unkeyedHash, 0);
            blake2bunkeyed.reset();

            if (!Arrays.areEqual(Hex.decode(unkeyedTestVectors[i][0]),
                unkeyedHash))
            {
                fail("BLAKE2b mismatch on test vector ",
                    unkeyedTestVectors[i][0],
                    new String(Hex.encode(unkeyedHash)));
            }
        }

        cloneTest();
        resetTest();
        testNullKeyVsUnkeyed();
        testLengthConstruction();
    }

    private void cloneTest()
    {
        Blake2bDigest blake2bCloneSource = new Blake2bDigest(Hex.decode(keyedTestVectors[3][1]), 16, Hex.decode("000102030405060708090a0b0c0d0e0f"), Hex.decode("101112131415161718191a1b1c1d1e1f"));
        byte[] expected = Hex.decode("b6d48ed5771b17414c4e08bd8d8a3bc4");

        checkClone(blake2bCloneSource, expected);

        // just digest size
        blake2bCloneSource = new Blake2bDigest(160);
        expected = Hex.decode("64202454e538279b21cea0f5a7688be656f8f484");
        checkClone(blake2bCloneSource, expected);

        // null salt and personalisation
        blake2bCloneSource = new Blake2bDigest(Hex.decode(keyedTestVectors[3][1]), 16, null, null);
        expected = Hex.decode("2b4a081fae2d7b488f5eed7e83e42a20");
        checkClone(blake2bCloneSource, expected);

        // null personalisation
        blake2bCloneSource = new Blake2bDigest(Hex.decode(keyedTestVectors[3][1]), 16, Hex.decode("000102030405060708090a0b0c0d0e0f"), null);
        expected = Hex.decode("00c3a2a02fcb9f389857626e19d706f6");
        checkClone(blake2bCloneSource, expected);

        // null salt
        blake2bCloneSource = new Blake2bDigest(Hex.decode(keyedTestVectors[3][1]), 16, null, Hex.decode("101112131415161718191a1b1c1d1e1f"));
        expected = Hex.decode("f445ec9c062a3c724f8fdef824417abb");
        checkClone(blake2bCloneSource, expected);
    }

    private void checkClone(Blake2bDigest blake2bCloneSource, byte[] expected)
    {
        byte[] message = Hex.decode(keyedTestVectors[3][0]);

        blake2bCloneSource.update(message, 0, message.length);

        byte[] hash = new byte[blake2bCloneSource.getDigestSize()];

        Blake2bDigest digClone = new Blake2bDigest(blake2bCloneSource);

        blake2bCloneSource.doFinal(hash, 0);
        if (!areEqual(expected, hash))
        {
            fail("clone source not correct");
        }

        digClone.doFinal(hash, 0);
        if (!areEqual(expected, hash))
        {
            fail("clone not correct");
        }
    }

    private void testLengthConstruction()
    {
        try
        {
            new Blake2bDigest(-1);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512", e.getMessage());
        }

        try
        {
            new Blake2bDigest(9);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512", e.getMessage());
        }

        try
        {
            new Blake2bDigest(520);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512", e.getMessage());
        }

        try
        {
            new Blake2bDigest(null, -1, null, null);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Invalid digest length (required: 1 - 64)", e.getMessage());
        }

        try
        {
            new Blake2bDigest(null, 65, null, null);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("Invalid digest length (required: 1 - 64)", e.getMessage());
        }
    }

    private void testNullKeyVsUnkeyed()
    {
        byte[] abc = Strings.toByteArray("abc");

        for (int i = 1; i != 64; i++)
        {
            Blake2bDigest dig1 = new Blake2bDigest(i * 8);
            Blake2bDigest dig2 = new Blake2bDigest(null, i, null, null);

            byte[] out1 = new byte[i];
            byte[] out2 = new byte[i];

            dig1.update(abc, 0, abc.length);
            dig2.update(abc, 0, abc.length);

            dig1.doFinal(out1, 0);
            dig2.doFinal(out2, 0);

            isTrue(Arrays.areEqual(out1, out2));
        }
    }

    private void resetTest()
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
        Blake2bDigest digest = new Blake2bDigest(key);
        digest.update(input, 0, input.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        // Using a second instance, hash the input without calling doFinal()
        Blake2bDigest digest1 = new Blake2bDigest(key);
        digest1.update(input, 0, input.length);
        // Reset the second instance and hash the input again
        digest1.reset();
        digest1.update(input, 0, input.length);
        byte[] hash1 = new byte[digest.getDigestSize()];
        digest1.doFinal(hash1, 0);
        // The hashes should be identical
        if (!Arrays.areEqual(hash, hash1))
        {
            fail("state was not reset");
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new Blake2bDigestTest());
    }
}
