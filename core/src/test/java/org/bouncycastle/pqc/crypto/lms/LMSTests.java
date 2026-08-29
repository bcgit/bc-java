package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

public class LMSTests
    extends TestCase
{
    public void testCoefFunc()
        throws Exception
    {
        byte[] S = Hex.decodeStrict("1234");
        TestCase.assertEquals(0, LM_OTS.coef(S, 7, 1));
        TestCase.assertEquals(1, LM_OTS.coef(S, 0, 4));
    }

    public void testPrivateKeyRound()
        throws Exception
    {
        LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");

        LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
        LMOtsPublicKey publicKey = LM_OTS.lms_ots_generatePublicKey(privateKey);

        byte[] ms = new byte[32];
        for (int t = 0; t < ms.length; t++)
        {
            ms[t] = (byte)t;
        }

        LMSContext ctx = privateKey.getSignatureContext(null, null);

        ctx.update(ms, 0, ms.length);

        LMOtsSignature sig = LM_OTS.lm_ots_generate_signature(privateKey, ctx.getQ(), ctx.getC());
        assertTrue(LM_OTS.lm_ots_validate_signature(publicKey, sig, ms, false));

        // Recreate signature
        {
            byte[] recreatedSignature = sig.getEncoded();
            assertTrue(LM_OTS.lm_ots_validate_signature(publicKey, LMOtsSignature.getInstance(recreatedSignature), ms, false));
        }

        // Recreate public key.
        {
            byte[] recreatedPubKey = Arrays.clone(publicKey.getEncoded());
            assertTrue(LM_OTS.lm_ots_validate_signature(LMOtsPublicKey.getInstance(recreatedPubKey), sig, ms, false));
        }

        // Vandalise signature
        {
            byte[] vandalisedSignature = sig.getEncoded();
            vandalisedSignature[256] ^= 1; // Single bit error
            assertFalse(LM_OTS.lm_ots_validate_signature(publicKey, LMOtsSignature.getInstance(vandalisedSignature), ms, false));
        }

        // Vandalise public key.
        {
            byte[] vandalisedPubKey = Arrays.clone(publicKey.getEncoded());
            vandalisedPubKey[50] ^= 1;
            assertFalse(LM_OTS.lm_ots_validate_signature(LMOtsPublicKey.getInstance(vandalisedPubKey), sig, ms, false));
        }


        //
        // check incorrect alg type is detected.
        //
        try
        {
            byte[] vandalisedPubKey = Arrays.clone(publicKey.getEncoded());
            vandalisedPubKey[3] += 1;
            LM_OTS.lm_ots_validate_signature(LMOtsPublicKey.getInstance(vandalisedPubKey), sig, ms, false);
            assertTrue("Must fail as public key type not match signature type.", false);
        }
        catch (LMSException ex)
        {
            assertTrue(ex.getMessage().contains("public key and signature ots types do not match"));
        }


    }


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
        LMSPrivateKeyParameters lmsPrivateKey = LMS.generateKeys(LMSigParameters.getParametersForType(5), LMOtsParameters.getParametersForType(4), level, Hex.decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);
        LMSPublicKeyParameters publicKey = lmsPrivateKey.getPublicKey();

        lmsPrivateKey.extractKeyShard(3);

        LMSSignature signature = LMS.generateSign(lmsPrivateKey, msg);
        assertTrue(LMS.verifySignature(publicKey, signature, msg));

        // Serialize / Deserialize
        assertTrue(LMS.verifySignature(LMSPublicKeyParameters.getInstance(publicKey.getEncoded()), LMSSignature.getInstance(signature.getEncoded()), msg));

        //
        // Vandalise signature.
        //
        {
            byte[] bustedSig = signature.getEncoded().clone();
            bustedSig[100] ^= 1;
            assertFalse(LMS.verifySignature(publicKey, LMSSignature.getInstance(bustedSig), msg));
        }

        //
        // Vandalise message
        //
        {
            byte[] msg2 = msg.clone();
            msg2[10] ^= 1;
            assertFalse(LMS.verifySignature(publicKey, signature, msg2));
        }

    }


    public void testContextSingleUse()
        throws Exception
    {
        LMOtsParameters parameter = LMOtsParameters.sha256_n32_w4;

        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");

        LMOtsPrivateKey privateKey = new LMOtsPrivateKey(parameter, I, 0, seed);
        LMOtsPublicKey publicKey = LM_OTS.lms_ots_generatePublicKey(privateKey);

        byte[] ms = new byte[32];
        for (int t = 0; t < ms.length; t++)
        {
            ms[t] = (byte)t;
        }

        LMSContext ctx = privateKey.getSignatureContext(null, null);

        ctx.update(ms, 0, ms.length);

        LMOtsSignature sig = LM_OTS.lm_ots_generate_signature(privateKey, ctx.getQ(), ctx.getC());
        assertTrue(LM_OTS.lm_ots_validate_signature(publicKey, sig, ms, false));

        try
        {
            ctx.update((byte)1);
            fail("Digest reuse after signature taken.");
        }
        catch (NullPointerException npe)
        {
            assertTrue(true);
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

        LMSPrivateKeyParameters privateKey = LMS.generateKeys(sigParams, otsParams, 0, I, seed);
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
        LMSSignature sigFromDecoded = LMS.generateSign(decoded, msg);
        assertTrue(LMS.verifySignature(publicKey, sigFromDecoded, msg));

        LMSPrivateKeyParameters fresh = LMS.generateKeys(sigParams, otsParams, 0, I, seed);
        assertTrue(Arrays.areEqual(sigFromDecoded.getEncoded(), LMS.generateSign(fresh, msg).getEncoded()));

        // An encoding with no trailing cache - what an older release writes - must still decode
        // and sign correctly.
        byte[] legacyEnc = Composer.compose()
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
        assertTrue(LMS.verifySignature(publicKey, LMS.generateSign(legacy, msg), msg));
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

        byte[] unknownSigType = Composer.compose()
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

        byte[] unknownOtsType = Composer.compose()
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

        byte[] beyondLimit = Composer.compose()
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

        byte[] truncated = Composer.compose()
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
        // A cache whose count and length are in range but whose node values are not the ones the key
        // derives is refused rather than primed into the tree (github #2414).
        //
        byte[] zeroed = Composer.compose()
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
     * Every single-byte corruption of the tree cache is rejected at decode, and the one-time index q
     * and its limit maxQ are range checked. Both were unchecked before github #2414: see the
     * org.bouncycastle.crypto.params twin of this test for the detail.
     */
    public void testPrivateKeyDecodeValidation()
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
            byte[] corrupt = Arrays.clone(enc);
            corrupt[cacheOff + (r - 1) * m] ^= 0x01;
            try
            {
                LMSPrivateKeyParameters.getInstance(corrupt);
                fail("no exception on corrupt cache node " + r);
            }
            catch (IOException e)
            {
                assertTrue(e.getMessage().startsWith("LMS private key tree cache inconsistent at node"));
            }
        }

        byte[] I = Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534");
        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        int twoToH = 1 << sigParams.getH();
        int[][] bad = { { twoToH + 1, 1000 }, { -1, twoToH }, { Integer.MIN_VALUE, twoToH },
                        { 0, twoToH + 1 }, { 0, -1 }, { 4, 3 } };
        for (int i = 0; i != bad.length; i++)
        {
            byte[] bogus = Composer.compose()
                .u32str(0)
                .u32str(sigParams.getType())
                .u32str(otsParams.getType())
                .bytes(I)
                .u32str(bad[i][0])
                .u32str(bad[i][1])
                .u32str(seed.length)
                .bytes(seed)
                .build();
            try
            {
                LMSPrivateKeyParameters.getInstance(bogus);
                fail("no exception on q=" + bad[i][0] + " maxQ=" + bad[i][1]);
            }
            catch (IOException e)
            {
                assertTrue(e.getMessage().startsWith("LMS private key q/maxQ out of range"));
            }
        }

        // the untouched encoding still decodes and primes
        assertTrue(LMSPrivateKeyParameters.getInstance(enc).isTreeCachePrimed());
    }

}
