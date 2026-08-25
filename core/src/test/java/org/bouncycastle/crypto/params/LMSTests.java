package org.bouncycastle.crypto.params;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
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

        byte[] atLimit = LMSVectorUtils.compose()
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
        assertTrue(LMSPrivateKeyParameters.getInstance(atLimit).isTreeCachePrimed());

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
