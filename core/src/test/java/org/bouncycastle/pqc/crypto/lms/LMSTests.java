package org.bouncycastle.pqc.crypto.lms;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
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


        //  Vandalise signature
        {

            byte[] vandalisedSignature = sig.getEncoded(); // Arrays.clone(sig);
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

}
