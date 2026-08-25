package org.bouncycastle.crypto.signers.lms;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tests of the LM-OTS one-time signature layer (RFC 8554 sec. 4), which is package-private.
 */
public class LMOtsTests
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
}
