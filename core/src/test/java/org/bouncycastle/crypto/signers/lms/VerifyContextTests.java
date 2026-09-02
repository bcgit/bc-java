package org.bouncycastle.crypto.signers.lms;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.signers.LMSSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

/**
 * The checks RFC 8554 sec. 5.4.2 requires of an LMS signature before it is processed: step 2g, the
 * signature's LMS typecode must be the one from the public key, and step 2i, its leaf number q must
 * be inside the tree. Both were absent - the path computation took its height and digest from the
 * parameter set the signature named, and an out-of-range q was left to the candidate-root
 * comparison to catch.
 */
public class VerifyContextTests
    extends TestCase
{
    private static final byte[] MSG = Hex.decode("48656c6c6f20776f726c64");

    /**
     * lms_sha256_n32_h5 (0x05) and lms_shake256_n32_h5 (0x0f) share m and h, so swapping one
     * typecode for the other leaves a signature of exactly the right length: it parses, and only
     * the step 2g check stands between it and the path computation.
     */
    public void testSignatureTypeMustMatchPublicKey()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = keyPair();
        LMSPublicKeyParameters pub = (LMSPublicKeyParameters)kp.getPublic();
        byte[] sig = sign(kp, MSG);

        // u32str(q) || ots_signature || u32str(lms typecode) || path[]
        int typeOff = sig.length - 4 - LMSigParameters.lms_sha256_n32_h5.getH() * LMSigParameters.lms_sha256_n32_h5.getM();
        assertEquals("expected the sha256 h5 typecode at that offset",
            LMSigParameters.lms_sha256_n32_h5.getType(), Pack.bigEndianToInt(sig, typeOff));

        byte[] swapped = Arrays.clone(sig);
        Pack.intToBigEndian(LMSigParameters.lms_shake256_n32_h5.getType(), swapped, typeOff);

        LMSSignature parsed = LMSSignature.getInstance(swapped);
        assertEquals("the swap should still parse", LMSigParameters.lms_shake256_n32_h5.getType(),
            parsed.getParameter().getType());

        try
        {
            LMSEngine.generateVerifyContext(pub, parsed);
            fail("a signature naming a different LMS type was accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("lms type from lms signature does not match lms type from public key", e.getMessage());
        }

        // and the JCA-facing contract is unchanged: reported, never thrown
        LMSSigner verifier = new LMSSigner();
        verifier.init(false, pub);
        assertFalse(verifier.verifySignature(MSG, swapped));
    }

    /**
     * q is the first field of the signature, so raising it past 2^h leaves the length untouched.
     */
    public void testLeafNumberMustBeInsideTheTree()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = keyPair();
        LMSPublicKeyParameters pub = (LMSPublicKeyParameters)kp.getPublic();
        byte[] sig = sign(kp, MSG);

        int twoToH = 1 << LMSigParameters.lms_sha256_n32_h5.getH();
        int[] outside = new int[]{ twoToH, twoToH + 1, Integer.MAX_VALUE, -1 };

        for (int i = 0; i != outside.length; i++)
        {
            byte[] moved = Arrays.clone(sig);
            Pack.intToBigEndian(outside[i], moved, 0);

            try
            {
                LMSEngine.generateVerifyContext(pub, LMSSignature.getInstance(moved));
                fail("a signature with q = " + outside[i] + " was accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("lms leaf number q from lms signature is outside the public key's tree",
                    e.getMessage());
            }

            LMSSigner verifier = new LMSSigner();
            verifier.init(false, pub);
            assertFalse(verifier.verifySignature(MSG, moved));
        }
    }

    /**
     * The untouched signature is unaffected by either check.
     */
    public void testWellFormedSignatureStillVerifies()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = keyPair();
        byte[] sig = sign(kp, MSG);

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue(verifier.verifySignature(MSG, sig));

        assertNotNull(LMSEngine.generateVerifyContext(
            (LMSPublicKeyParameters)kp.getPublic(), LMSSignature.getInstance(sig)));
    }

    private static AsymmetricCipherKeyPair keyPair()
    {
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(new LMSKeyGenerationParameters(new LMSParameters(
            LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w8), new SecureRandom()));
        return gen.generateKeyPair();
    }

    private static byte[] sign(AsymmetricCipherKeyPair kp, byte[] message)
    {
        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        return signer.generateSignature(message);
    }
}
