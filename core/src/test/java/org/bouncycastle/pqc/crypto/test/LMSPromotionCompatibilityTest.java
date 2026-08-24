package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;

/**
 * The LMS/HSS implementation under org.bouncycastle.crypto is a copy of the deprecated
 * org.bouncycastle.pqc.crypto.lms one, so the two must agree byte for byte on every encoding and
 * each must verify what the other signed. This test pins that down over the whole parameter-set
 * matrix, and is the guard against the copy drifting from the original while both ship.
 */
public class LMSPromotionCompatibilityTest
    extends TestCase
{
    private static final byte[] MESSAGE = org.bouncycastle.util.Strings.toByteArray(
        "the quick brown fox jumped over the lazy dog");

    private static final org.bouncycastle.crypto.params.LMSigParameters[] SIG =
        {
            org.bouncycastle.crypto.params.LMSigParameters.lms_sha256_n32_h5,
            org.bouncycastle.crypto.params.LMSigParameters.lms_sha256_n32_h10,
            org.bouncycastle.crypto.params.LMSigParameters.lms_sha256_n24_h5,
            org.bouncycastle.crypto.params.LMSigParameters.lms_shake256_n32_h5,
            org.bouncycastle.crypto.params.LMSigParameters.lms_shake256_n24_h5
        };

    private static final org.bouncycastle.crypto.params.LMOtsParameters[] OTS =
        {
            org.bouncycastle.crypto.params.LMOtsParameters.sha256_n32_w1,
            org.bouncycastle.crypto.params.LMOtsParameters.sha256_n32_w2,
            org.bouncycastle.crypto.params.LMOtsParameters.sha256_n32_w4,
            org.bouncycastle.crypto.params.LMOtsParameters.sha256_n32_w8
        };

    /**
     * The same seed drives both implementations, so a matching set of keys must come out with
     * identical X.509 / PKCS#8 encodings, and each side must verify the other's signature.
     */
    public void testLMSKeysAndSignaturesMatchAcrossImplementations()
        throws Exception
    {
        for (int i = 0; i != SIG.length; i++)
        {
            for (int j = 0; j != OTS.length; j++)
            {
                String label = SIG[i].getType() + "/" + OTS[j].getType();
                byte[] seed = seedFor(i * OTS.length + j);

                org.bouncycastle.crypto.generators.LMSKeyPairGenerator newGen =
                    new org.bouncycastle.crypto.generators.LMSKeyPairGenerator();
                newGen.init(new org.bouncycastle.crypto.params.LMSKeyGenerationParameters(
                    new org.bouncycastle.crypto.params.LMSParameters(SIG[i], OTS[j]), fixedRandom(seed)));
                AsymmetricCipherKeyPair newKp = newGen.generateKeyPair();

                org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator oldGen =
                    new org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator();
                oldGen.init(new org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters(
                    new org.bouncycastle.pqc.crypto.lms.LMSParameters(
                        org.bouncycastle.pqc.crypto.lms.LMSigParameters.getParametersForType(SIG[i].getType()),
                        org.bouncycastle.pqc.crypto.lms.LMOtsParameters.getParametersForType(OTS[j].getType())),
                    fixedRandom(seed)));
                AsymmetricCipherKeyPair oldKp = oldGen.generateKeyPair();

                byte[] newPub = SubjectPublicKeyInfoFactory
                    .createSubjectPublicKeyInfo(newKp.getPublic()).getEncoded();
                byte[] oldPub = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory
                    .createSubjectPublicKeyInfo(oldKp.getPublic()).getEncoded();
                assertTrue(label + ": public key encodings differ", Arrays.areEqual(newPub, oldPub));

                byte[] newPriv = PrivateKeyInfoFactory.createPrivateKeyInfo(newKp.getPrivate()).getEncoded();
                byte[] oldPriv = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory
                    .createPrivateKeyInfo(oldKp.getPrivate()).getEncoded();
                assertTrue(label + ": private key encodings differ", Arrays.areEqual(newPriv, oldPriv));

                // each side's key factory must accept the other side's encoding
                assertNotNull(label + ": promoted factory rejected the deprecated public key",
                    PublicKeyFactory.createKey(oldPub));
                assertNotNull(label + ": promoted factory rejected the deprecated private key",
                    PrivateKeyFactory.createKey(oldPriv));
                assertNotNull(label + ": deprecated factory rejected the promoted public key",
                    org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(newPub));
                assertNotNull(label + ": deprecated factory rejected the promoted private key",
                    org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(newPriv));

                // identical signatures, and each verifies the other's
                org.bouncycastle.crypto.signers.LMSSigner newSigner =
                    new org.bouncycastle.crypto.signers.LMSSigner();
                newSigner.init(true, newKp.getPrivate());
                byte[] newSig = newSigner.generateSignature(MESSAGE);

                org.bouncycastle.pqc.crypto.lms.LMSSigner oldSigner =
                    new org.bouncycastle.pqc.crypto.lms.LMSSigner();
                oldSigner.init(true, oldKp.getPrivate());
                byte[] oldSig = oldSigner.generateSignature(MESSAGE);

                assertTrue(label + ": signatures differ", Arrays.areEqual(newSig, oldSig));

                org.bouncycastle.crypto.signers.LMSSigner newVerifier =
                    new org.bouncycastle.crypto.signers.LMSSigner();
                newVerifier.init(false, newKp.getPublic());
                assertTrue(label + ": promoted verifier rejected the deprecated signature",
                    newVerifier.verifySignature(MESSAGE, oldSig));

                org.bouncycastle.pqc.crypto.lms.LMSSigner oldVerifier =
                    new org.bouncycastle.pqc.crypto.lms.LMSSigner();
                oldVerifier.init(false, oldKp.getPublic());
                assertTrue(label + ": deprecated verifier rejected the promoted signature",
                    oldVerifier.verifySignature(MESSAGE, newSig));
            }
        }
    }

    /**
     * The same for the HSS multi-tree variant, whose private key encoding carries the per-level
     * index state - the part most likely to drift.
     */
    public void testHSSKeysAndSignaturesMatchAcrossImplementations()
        throws Exception
    {
        byte[] seed = seedFor(99);

        org.bouncycastle.crypto.params.LMSParameters[] newParams = new org.bouncycastle.crypto.params.LMSParameters[]
            {
                new org.bouncycastle.crypto.params.LMSParameters(SIG[0], OTS[0]),
                new org.bouncycastle.crypto.params.LMSParameters(SIG[0], OTS[1])
            };
        org.bouncycastle.crypto.generators.HSSKeyPairGenerator newGen =
            new org.bouncycastle.crypto.generators.HSSKeyPairGenerator();
        newGen.init(new org.bouncycastle.crypto.params.HSSKeyGenerationParameters(newParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair newKp = newGen.generateKeyPair();

        org.bouncycastle.pqc.crypto.lms.LMSParameters[] oldParams = new org.bouncycastle.pqc.crypto.lms.LMSParameters[]
            {
                new org.bouncycastle.pqc.crypto.lms.LMSParameters(
                    org.bouncycastle.pqc.crypto.lms.LMSigParameters.getParametersForType(SIG[0].getType()),
                    org.bouncycastle.pqc.crypto.lms.LMOtsParameters.getParametersForType(OTS[0].getType())),
                new org.bouncycastle.pqc.crypto.lms.LMSParameters(
                    org.bouncycastle.pqc.crypto.lms.LMSigParameters.getParametersForType(SIG[0].getType()),
                    org.bouncycastle.pqc.crypto.lms.LMOtsParameters.getParametersForType(OTS[1].getType()))
            };
        org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator oldGen =
            new org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator();
        oldGen.init(new org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters(oldParams, fixedRandom(seed)));
        AsymmetricCipherKeyPair oldKp = oldGen.generateKeyPair();

        byte[] newPub = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newKp.getPublic()).getEncoded();
        byte[] oldPub = org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory
            .createSubjectPublicKeyInfo(oldKp.getPublic()).getEncoded();
        assertTrue("HSS public key encodings differ", Arrays.areEqual(newPub, oldPub));

        byte[] newPriv = PrivateKeyInfoFactory.createPrivateKeyInfo(newKp.getPrivate()).getEncoded();
        byte[] oldPriv = org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory
            .createPrivateKeyInfo(oldKp.getPrivate()).getEncoded();
        assertTrue("HSS private key encodings differ", Arrays.areEqual(newPriv, oldPriv));

        assertNotNull("promoted factory rejected the deprecated HSS public key", PublicKeyFactory.createKey(oldPub));
        assertNotNull("promoted factory rejected the deprecated HSS private key", PrivateKeyFactory.createKey(oldPriv));

        org.bouncycastle.crypto.signers.HSSSigner newSigner = new org.bouncycastle.crypto.signers.HSSSigner();
        newSigner.init(true, newKp.getPrivate());
        byte[] newSig = newSigner.generateSignature(MESSAGE);

        org.bouncycastle.pqc.crypto.lms.HSSSigner oldSigner = new org.bouncycastle.pqc.crypto.lms.HSSSigner();
        oldSigner.init(true, oldKp.getPrivate());
        byte[] oldSig = oldSigner.generateSignature(MESSAGE);

        assertTrue("HSS signatures differ", Arrays.areEqual(newSig, oldSig));

        org.bouncycastle.crypto.signers.HSSSigner newVerifier = new org.bouncycastle.crypto.signers.HSSSigner();
        newVerifier.init(false, newKp.getPublic());
        assertTrue("promoted verifier rejected the deprecated HSS signature",
            newVerifier.verifySignature(MESSAGE, oldSig));

        org.bouncycastle.pqc.crypto.lms.HSSSigner oldVerifier = new org.bouncycastle.pqc.crypto.lms.HSSSigner();
        oldVerifier.init(false, oldKp.getPublic());
        assertTrue("deprecated verifier rejected the promoted HSS signature",
            oldVerifier.verifySignature(MESSAGE, newSig));
    }

    /**
     * The promoted signers implement org.bouncycastle.crypto.Signer rather than the pqc
     * MessageSigner, so the streaming path must produce exactly what the one-shot call does.
     */
    public void testStreamingMatchesOneShot()
        throws Exception
    {
        org.bouncycastle.crypto.generators.LMSKeyPairGenerator gen =
            new org.bouncycastle.crypto.generators.LMSKeyPairGenerator();
        gen.init(new org.bouncycastle.crypto.params.LMSKeyGenerationParameters(
            new org.bouncycastle.crypto.params.LMSParameters(SIG[0], OTS[0]), fixedRandom(seedFor(7))));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        org.bouncycastle.crypto.signers.LMSSigner signer = new org.bouncycastle.crypto.signers.LMSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);
        byte[] streamed = signer.generateSignature();

        org.bouncycastle.crypto.signers.LMSSigner verifier = new org.bouncycastle.crypto.signers.LMSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("streamed signature did not verify through the streaming path",
            verifier.verifySignature(streamed));

        // generateSignature() resets the buffer, so a second signature over the same message is
        // over the message alone and not the message twice - it must verify one-shot as well
        verifier.init(false, kp.getPublic());
        assertTrue("streamed signature did not verify one-shot", verifier.verifySignature(MESSAGE, streamed));
    }

    private static byte[] seedFor(int n)
    {
        byte[] seed = new byte[64];
        for (int i = 0; i != seed.length; i++)
        {
            seed[i] = (byte)(n * 31 + i);
        }
        return seed;
    }

    private static SecureRandom fixedRandom(byte[] seed)
    {
        return new org.bouncycastle.util.test.FixedSecureRandom(
            new org.bouncycastle.util.test.FixedSecureRandom.Source[]
                { new org.bouncycastle.util.test.FixedSecureRandom.Data(Arrays.concatenate(seed, seed, seed, seed)) });
    }
}
