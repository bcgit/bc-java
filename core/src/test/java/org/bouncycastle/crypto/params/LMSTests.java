package org.bouncycastle.crypto.params;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.signers.lms.LMSSignature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.signers.LMSSigner;

public class LMSTests
    extends TestCase
{



    public void testLMS()
        throws Exception
    {
        byte[] msg = Hex.decode("54686520656e756d65726174696f6e20\n" +
            "696e2074686520436f6e737469747574\n" +
            "696f6e2c206f66206365727461696e20\n" +
            "7269676874732c207368616c6c206e6f\n" +
            "7420626520636f6e7374727565642074\n" +
            "6f2064656e79206f7220646973706172\n" +
            "616765206f7468657273207265746169\n" +
            "6e6564206279207468652070656f706c\n" +
            "652e0a");

        byte[] seed = Hex.decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
        int level = 1;
        LMSPrivateKeyParameters lmsPrivateKey = lmsKey(LMSigParameters.getParametersForType(5), LMOtsParameters.getParametersForType(4), level, Hex.decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);
        LMSPublicKeyParameters publicKey = lmsPrivateKey.getPublicKey();

        lmsPrivateKey.extractKeyShard(3);

        byte[] signature = sign(lmsPrivateKey, msg);
        assertTrue(verify(publicKey, signature, msg));

        // Serialize / Deserialize
        assertTrue(verify(LMSPublicKeyParameters.getInstance(publicKey.getEncoded()), signature, msg));

        //
        // Vandalise signature.
        //
        {
            byte[] bustedSig = signature.clone();
            bustedSig[100] ^= 1;
            assertFalse(verify(publicKey, bustedSig, msg));
        }

        //
        // Vandalise message
        //
        {
            byte[] msg2 = msg.clone();
            msg2[10] ^= 1;
            assertFalse(verify(publicKey, signature, msg2));
        }

    }



    /**
     * Regression test for https://github.com/bcgit/bc-java/issues/2365 - getEncoded() must carry
     * the top of the Merkle tree so that the first signature made after a key is decoded does not
     * have to rebuild the whole tree (which costs about as much as key generation). Also checks
     * that the legacy version 0 encoding, which carries no cache, is still accepted.
     */
    public void testTreeCachePersistence()
        throws Exception
    {
        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");
        byte[] msg = Hex.decode("54686520656e756d65726174696f6e20696e2074686520436f6e737469747574");

        LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
        LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;

        LMSPrivateKeyParameters privateKey = lmsKey(sigParams, otsParams, 0, I, seed);
        LMSPublicKeyParameters publicKey = privateKey.getPublicKey();

        int h = sigParams.getH();
        int m = sigParams.getM();
        int cacheTop = Math.min(64, 1 << (h + 1));

        byte[] enc = privateKey.getEncoded();

        // 72 byte body + u32 node count + (cacheTop - 1) nodes of m bytes each. The version stays 0
        // and the cache is appended as trailing data, so releases that predate it still read the
        // key - they stop at the master secret - and simply do not see the cache.
        assertEquals(0, enc[0]);
        assertEquals(0, enc[1]);
        assertEquals(0, enc[2]);
        assertEquals(0, enc[3]);
        assertEquals(72 + 4 + (cacheTop - 1) * m, enc.length);

        // Decoding primes the cache - this is the fix; without it the decoded key's cache is empty
        // and the first signature rebuilds the whole tree.
        LMSPrivateKeyParameters decoded = LMSPrivateKeyParameters.getInstance(enc);
        assertTrue("decoded key tree cache should be primed", decoded.isTreeCachePrimed());

        // The decoded key signs correctly and byte-identically to a fresh key at the same index.
        byte[] sigFromDecoded = sign(decoded, msg);
        assertTrue(verify(publicKey, sigFromDecoded, msg));

        LMSPrivateKeyParameters fresh = lmsKey(sigParams, otsParams, 0, I, seed);
        assertTrue(Arrays.areEqual(sigFromDecoded, sign(fresh, msg)));

        // An encoding with no trailing cache - what an older release writes - must still decode
        // and sign correctly.
        byte[] legacyEnc = LMSVectorUtils.compose()
            .u32str(0)
            .u32str(sigParams.getType())
            .u32str(otsParams.getType())
            .bytes(I)
            .u32str(0)
            .u32str(1 << h)
            .u32str(seed.length)
            .bytes(seed)
            .build();
        assertEquals(72, legacyEnc.length);

        LMSPrivateKeyParameters legacy = LMSPrivateKeyParameters.getInstance(legacyEnc);
        assertFalse("encoding without trailing data carries no cache", legacy.isTreeCachePrimed());
        assertTrue(verify(publicKey, sign(legacy, msg), msg));
    }

    /**
     * A private key encoding carrying an unknown LMS or LM-OTS type code must be rejected with the
     * declared IOException, not leak a NullPointerException out of getInstance (matching the guards
     * already present in LMSPublicKeyParameters / LMSSignature / LMOtsSignature).
     */
    public void testMalformedPrivateKeyTypeCode()
        throws Exception
    {
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");
        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");

        byte[] unknownSigType = LMSVectorUtils.compose()
            .u32str(0)
            .u32str(0x7fffffff) // bogus LMS type code
            .u32str(LMOtsParameters.sha256_n32_w4.getType())
            .bytes(I)
            .u32str(0)
            .u32str(32)
            .u32str(seed.length)
            .bytes(seed)
            .build();
        try
        {
            LMSPrivateKeyParameters.getInstance(unknownSigType);
            fail("no exception on unknown LMS type code");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().startsWith("unknown LMS type code"));
        }

        byte[] unknownOtsType = LMSVectorUtils.compose()
            .u32str(0)
            .u32str(LMSigParameters.lms_sha256_n32_h5.getType())
            .u32str(0x7fffffff) // bogus LM-OTS type code
            .bytes(I)
            .u32str(0)
            .u32str(32)
            .u32str(seed.length)
            .bytes(seed)
            .build();
        try
        {
            LMSPrivateKeyParameters.getInstance(unknownOtsType);
            fail("no exception on unknown LM-OTS type code");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().startsWith("unknown LM-OTS type code"));
        }
    }

    public void testMalformedPrivateKeyTreeCache()
        throws Exception
    {
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");
        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");

        LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h10;
        LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w4;
        int m = sigParams.getM();

        //
        // The number of nodes cached is capped by LMSPrivateKeyParameters' interned-key table, so
        // read it off a freshly generated key of the same parameters rather than hard-coding it -
        // the limit moves if that table is resized.
        //
        LMSKeyPairGenerator limitGen = new LMSKeyPairGenerator();
        limitGen.init(new LMSKeyGenerationParameters(new LMSParameters(sigParams, otsParams), new SecureRandom()));
        byte[] sampleEnc = ((LMSPrivateKeyParameters)limitGen.generateKeyPair().getPrivate()).getEncoded();
        int cacheCountLimit = Pack.bigEndianToInt(sampleEnc, 40 + m);

        //
        // A cache at the limit is accepted. The node values have to be the real ones: they are a
        // deterministic function of I, the master secret and the parameters, and are now checked
        // against each other at decode (github #2414), so the sample key's own encoding is used
        // rather than a run of dummy bytes.
        //
        assertEquals(cacheCountLimit, Pack.bigEndianToInt(sampleEnc, 40 + m));
        assertTrue(LMSPrivateKeyParameters.getInstance(sampleEnc).isTreeCachePrimed());

        byte[] beyondLimit = LMSVectorUtils.compose()
            .u32str(0)
            .u32str(sigParams.getType())
            .u32str(otsParams.getType())
            .bytes(I)
            .u32str(0)
            .u32str(1 << sigParams.getH())
            .u32str(seed.length)
            .bytes(seed)
            .u32str(cacheCountLimit + 1)
            .build();
        try
        {
            LMSPrivateKeyParameters.getInstance(beyondLimit);
            fail("no exception on over-sized tree cache");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().startsWith("tree cache node count out of range"));
        }

        byte[] truncated = LMSVectorUtils.compose()
            .u32str(0)
            .u32str(sigParams.getType())
            .u32str(otsParams.getType())
            .bytes(I)
            .u32str(0)
            .u32str(1 << sigParams.getH())
            .u32str(seed.length)
            .bytes(seed)
            .u32str(cacheCountLimit)
            .bytes(new byte[cacheCountLimit * m - 1])
            .build();
        try
        {
            LMSPrivateKeyParameters.getInstance(truncated);
            fail("no exception on truncated tree cache");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().startsWith("tree cache length exceeded"));
        }

        //
        // A cache whose count and length are both in range but whose node values are not the ones
        // the key derives is refused rather than primed into the tree. Every cached node has its
        // parent recomputed from it, so a single altered byte anywhere in the cache is caught -
        // swept over the whole cache below in testTreeCacheCorruptionRejected.
        //
        byte[] zeroed = LMSVectorUtils.compose()
            .u32str(0)
            .u32str(sigParams.getType())
            .u32str(otsParams.getType())
            .bytes(I)
            .u32str(0)
            .u32str(1 << sigParams.getH())
            .u32str(seed.length)
            .bytes(seed)
            .u32str(cacheCountLimit)
            .bytes(new byte[cacheCountLimit * m])
            .build();
        try
        {
            LMSPrivateKeyParameters.getInstance(zeroed);
            fail("no exception on a tree cache that does not match the key");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().startsWith("LMS private key tree cache inconsistent at node"));
        }
    }

    /**
     * Every single-byte corruption of the tree cache is rejected at decode. Before github #2414 the
     * cached node values were read but never checked, so a corrupt cache was primed into the tree:
     * altering the root changed the public key the key reported (and survived a re-encode), and
     * altering other nodes produced signatures that did not verify - both silently.
     */
    public void testTreeCacheCorruptionRejected()
        throws Exception
    {
        LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
        LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
        int m = sigParams.getM();

        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(new LMSKeyGenerationParameters(new LMSParameters(sigParams, otsParams), new SecureRandom()));
        LMSPrivateKeyParameters priv = (LMSPrivateKeyParameters)gen.generateKeyPair().getPrivate();
        byte[] enc = priv.getEncoded();

        int countOff = 40 + Pack.bigEndianToInt(enc, 36);
        int cacheCount = Pack.bigEndianToInt(enc, countOff);
        int cacheOff = countOff + 4;
        assertTrue("expected a primed cache to corrupt", cacheCount > 0);

        for (int r = 1; r <= cacheCount; r++)
        {
            for (int b = 0; b < m; b++)
            {
                byte[] corrupt = Arrays.clone(enc);
                corrupt[cacheOff + (r - 1) * m + b] ^= 0x01;
                try
                {
                    LMSPrivateKeyParameters.getInstance(corrupt);
                    fail("no exception on corrupt cache node " + r + " byte " + b);
                }
                catch (IOException e)
                {
                    assertTrue(e.getMessage().startsWith("LMS private key tree cache inconsistent at node"));
                }
            }
        }

        // the untouched encoding still decodes, primes and signs verifiably
        LMSPrivateKeyParameters decoded = LMSPrivateKeyParameters.getInstance(enc);
        assertTrue(decoded.isTreeCachePrimed());
        byte[] msg = Hex.decode("48656c6c6f");
        assertTrue(verify(priv.getPublicKey(), sign(decoded, msg), msg));
    }

    /**
     * The key parameter constructors apply the checks the decoder applies, so a key built directly
     * cannot be one the decoder would refuse. LMSPrivateKeyParameters accepted an identifier of any
     * length although the decoder reads exactly 16 bytes - such a key encoded but could not be read
     * back - and left q, maxQ and the seed length unchecked although all three are checked at
     * decode; HSSPrivateKeyParameters checked neither its level count nor that it had been given a
     * component key and a chaining signature per level, and then indexed both lists.
     */
    public void testKeyParameterConstructorsValidate()
        throws Exception
    {
        LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
        LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
        int twoToH = 1 << sigParams.getH();
        byte[] I = new byte[16];
        byte[] seed = new byte[sigParams.getM()];

        // the well-formed case is unaffected
        assertNotNull(new LMSPrivateKeyParameters(sigParams, otsParams, 0, I, twoToH, seed));

        expectBadArgument("LMS key identifier I must be 16 bytes", sigParams, otsParams, 0, new byte[15], twoToH, seed);
        expectBadArgument("LMS key identifier I must be 16 bytes", sigParams, otsParams, 0, new byte[17], twoToH, seed);
        expectBadArgument("LMS key identifier I must be 16 bytes", sigParams, otsParams, 0, null, twoToH, seed);
        expectBadArgument("LMS private key needs both parameter sets", sigParams, null, 0, I, twoToH, seed);
        expectBadArgument("master secret is less than " + sigParams.getM(),
            sigParams, otsParams, 0, I, twoToH, new byte[1]);
        expectBadArgument("LMS private key q/maxQ out of range: q=-1 maxQ=" + twoToH + " 2^h=" + twoToH,
            sigParams, otsParams, -1, I, twoToH, seed);
        expectBadArgument("LMS private key q/maxQ out of range: q=0 maxQ=" + (twoToH + 1) + " 2^h=" + twoToH,
            sigParams, otsParams, 0, I, twoToH + 1, seed);
        expectBadArgument("LMS private key q/maxQ out of range: q=5 maxQ=4 2^h=" + twoToH,
            sigParams, otsParams, 5, I, 4, seed);

        // and a key that survives the constructor round-trips through the decoder
        LMSPrivateKeyParameters key = new LMSPrivateKeyParameters(sigParams, otsParams, 0, I, twoToH, seed);
        assertNotNull(LMSPrivateKeyParameters.getInstance(key.getEncoded()));

        // HSS: level count, list sizes and the index pair
        List<LMSPrivateKeyParameters> one = new ArrayList<LMSPrivateKeyParameters>();
        one.add(key);
        List<LMSSignature> none = new ArrayList<LMSSignature>();

        expectBadHss("L value of HSS private key out of range: 0", 0, one, none, 0, twoToH);
        expectBadHss("L value of HSS private key out of range: 9", 9, one, none, 0, twoToH);
        expectBadHss("HSS private key needs one component key per level", 2, one, none, 0, twoToH);
        expectBadHss("HSS private key index out of range: index=5 indexLimit=4", 1, one, none, 5, 4);
        expectBadHss("HSS private key index out of range: index=-1 indexLimit=4", 1, one, none, -1, 4);

        // the well-formed single-level case still builds
        assertNotNull(new HSSPrivateKeyParameters(1, one, none, 0, twoToH));
    }

    private static void expectBadArgument(String message, LMSigParameters sigParams, LMOtsParameters otsParams,
        int q, byte[] I, int maxQ, byte[] seed)
    {
        try
        {
            new LMSPrivateKeyParameters(sigParams, otsParams, q, I, maxQ, seed);
            fail("no exception for: " + message);
        }
        catch (IllegalArgumentException e)
        {
            assertEquals(message, e.getMessage());
        }
    }

    private static void expectBadHss(String message, int l, List<LMSPrivateKeyParameters> keys,
        List<LMSSignature> sig, long index, long indexLimit)
    {
        try
        {
            new HSSPrivateKeyParameters(l, keys, sig, index, indexLimit);
            fail("no exception for: " + message);
        }
        catch (IllegalArgumentException e)
        {
            assertEquals(message, e.getMessage());
        }
    }

    /**
     * A tree cache node count that is not a complete top of tree - 2^k - 1 nodes - is refused at
     * decode. The consistency check recomputes a cached node from its two cached children, so a
     * node with no cached sibling pair above it would be read but never checked: at a count of 1
     * or 2 that is the root itself, so a corrupted root was primed and the key reported the wrong
     * public key, and at any even count it is the last node, so a corrupted one survived and was
     * carried forward by the next getEncoded(). This writer only ever emits 63, or 31 for a
     * height-5 shard.
     */
    public void testTreeCacheIncompleteTopOfTreeRejected()
        throws Exception
    {
        LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
        LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
        int m = sigParams.getM();

        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(new LMSKeyGenerationParameters(new LMSParameters(sigParams, otsParams), new SecureRandom()));
        LMSPrivateKeyParameters priv = (LMSPrivateKeyParameters)gen.generateKeyPair().getPrivate();
        byte[] enc = priv.getEncoded();

        int countOff = 40 + Pack.bigEndianToInt(enc, 36);
        int cacheCount = Pack.bigEndianToInt(enc, countOff);
        assertEquals("this writer should emit a full top of tree", 63, cacheCount);

        int[] incomplete = new int[]{ 1, 2, 4, 5, 6, 8, 30, 62 };
        for (int i = 0; i != incomplete.length; i++)
        {
            int count = incomplete[i];
            try
            {
                LMSPrivateKeyParameters.getInstance(withNodeCount(enc, countOff, m, count));
                fail("no exception on an incomplete tree cache of " + count + " nodes");
            }
            catch (IOException e)
            {
                assertEquals("tree cache node count is not a complete top of tree: " + count, e.getMessage());
            }
        }

        // the shapes this writer produces, and an absent cache, are still accepted
        int[] complete = new int[]{ 0, 3, 7, 15, 31, 63 };
        for (int i = 0; i != complete.length; i++)
        {
            LMSPrivateKeyParameters decoded =
                LMSPrivateKeyParameters.getInstance(withNodeCount(enc, countOff, m, complete[i]));
            assertTrue("complete top of tree of " + complete[i] + " nodes was refused",
                Arrays.areEqual(priv.getPublicKey().getEncoded(), decoded.getPublicKey().getEncoded()));
        }

        // a corrupted node in each refused shape is what the restriction is there to stop reaching
        // the tree: at count 1 and 2 the root, at count 62 the last node
        int[][] corruptCases = new int[][]{ { 1, 1 }, { 2, 1 }, { 62, 62 } };
        for (int i = 0; i != corruptCases.length; i++)
        {
            byte[] truncated = withNodeCount(enc, countOff, m, corruptCases[i][0]);
            truncated[countOff + 4 + (corruptCases[i][1] - 1) * m] ^= 0x01;
            try
            {
                LMSPrivateKeyParameters.getInstance(truncated);
                fail("corrupt node " + corruptCases[i][1] + " accepted at count " + corruptCases[i][0]);
            }
            catch (IOException e)
            {
                assertEquals("tree cache node count is not a complete top of tree: " + corruptCases[i][0],
                    e.getMessage());
            }
        }
    }

    /**
     * The passed in encoding with its tree cache cut down to the first nodeCount nodes.
     */
    private static byte[] withNodeCount(byte[] enc, int countOff, int m, int nodeCount)
    {
        byte[] rebuilt = new byte[countOff + 4 + nodeCount * m];

        System.arraycopy(enc, 0, rebuilt, 0, countOff);
        Pack.intToBigEndian(nodeCount, rebuilt, countOff);
        System.arraycopy(enc, countOff + 4, rebuilt, countOff + 4, nodeCount * m);

        return rebuilt;
    }

    /**
     * The one-time index q and its limit maxQ are range checked at decode. Before github #2414 they
     * were read with no check at all: q past the tree size gave a key that signed with an LM-OTS
     * leaf outside its own tree - the signature did not verify - and a negative q threw
     * NullPointerException / ArrayIndexOutOfBoundsException out of the signing call instead.
     */
    public void testPrivateKeyIndexRangeChecked()
        throws Exception
    {
        LMSigParameters sigParams = LMSigParameters.lms_sha256_n32_h5;
        LMOtsParameters otsParams = LMOtsParameters.sha256_n32_w1;
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");
        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        int twoToH = 1 << sigParams.getH();

        // q, maxQ pairs that must be refused
        int[][] bad = {
            { twoToH + 1, 1000 },           // q past the tree, maxQ raised past it
            { -1, twoToH },                 // negative q
            { Integer.MIN_VALUE, twoToH },  // negative q, wrapping
            { 0, twoToH + 1 },              // maxQ past the tree
            { 0, -1 },                      // negative maxQ
            { 4, 3 },                       // q past its own limit
        };
        for (int i = 0; i != bad.length; i++)
        {
            byte[] enc = coreKey(sigParams, otsParams, I, seed, bad[i][0], bad[i][1]);
            try
            {
                LMSPrivateKeyParameters.getInstance(enc);
                fail("no exception on q=" + bad[i][0] + " maxQ=" + bad[i][1]);
            }
            catch (IOException e)
            {
                assertTrue(e.getMessage().startsWith("LMS private key q/maxQ out of range"));
            }
        }

        // and the legitimate states still decode: unused, part-used, exhausted, and a shard
        int[][] good = { { 0, twoToH }, { 7, twoToH }, { twoToH, twoToH }, { 4, 8 } };
        for (int i = 0; i != good.length; i++)
        {
            LMSPrivateKeyParameters key = LMSPrivateKeyParameters.getInstance(
                coreKey(sigParams, otsParams, I, seed, good[i][0], good[i][1]));
            assertEquals(good[i][0], key.getIndex());
        }
    }

    private static byte[] coreKey(LMSigParameters sigParams, LMOtsParameters otsParams, byte[] I,
                                  byte[] seed, int q, int maxQ)
    {
        return LMSVectorUtils.compose()
            .u32str(0)
            .u32str(sigParams.getType())
            .u32str(otsParams.getType())
            .bytes(I)
            .u32str(q)
            .u32str(maxQ)
            .u32str(seed.length)
            .bytes(seed)
            .build();
    }


    private static byte[] sign(LMSPrivateKeyParameters key, byte[] message)
    {
        LMSSigner signer = new LMSSigner();
        signer.init(true, key);
        return signer.generateSignature(message);
    }

    private static boolean verify(LMSPublicKeyParameters key, byte[] signature, byte[] message)
    {
        LMSSigner signer = new LMSSigner();
        signer.init(false, key);
        return signer.verifySignature(message, signature);
    }

    // RFC 8554 sec. 5.2, Algorithm 5: an LMS private key positioned at index q.
    private static LMSPrivateKeyParameters lmsKey(LMSigParameters sigParams, LMOtsParameters otsParams, int q, byte[] I, byte[] seed)
    {
        return new LMSPrivateKeyParameters(sigParams, otsParams, q, I, 1 << sigParams.getH(), seed);
    }
}
