package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyPairGenerator;
import org.bouncycastle.pqc.crypto.aimer.AIMerParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerSigner;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mayo.MayoParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoSigner;
import org.bouncycastle.pqc.crypto.qruov.QRUOVKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qruov.QRUOVParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVSigner;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyPairGenerator;
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaSigner;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Regression test for github #2403. MAYO, SNOVA, QR-UOV, SQIsign and AIMer used
 * to return the NIST {@code crypto_sign} "sm" signed-message envelope from
 * generateSignature() - the signature with the message concatenated to it - and
 * to verify a buffer that merely started (for AIMer, ended) with a good
 * signature, ignoring whatever else it carried. That made the encoding
 * non-unique: given one valid signature, unlimited distinct byte strings
 * verified for the same message and key.
 * <p>
 * So for each scheme this asserts that what is produced is exactly the
 * parameter set's signature and that nothing else verifies - in particular the
 * envelope the scheme used to emit, which is the shape a caller would still have
 * lying around from an earlier release.
 * <p>
 * One parameter set per scheme: this is about the encoding, which the parameter
 * set does not vary, and SQIsign key generation is expensive.
 */
public class PqcSignatureEncodingTest
    extends TestCase
{
    private static final byte[] MESSAGE = Strings.toByteArray("no envelope, please");

    public void testMayo()
    {
        MayoParameters parameters = MayoParameters.mayo1;
        MayoKeyPairGenerator kpGen = new MayoKeyPairGenerator();
        kpGen.init(new MayoKeyGenerationParameters(new SecureRandom(), parameters));

        checkBareSignature("MAYO", kpGen, new MayoSigner(), new MayoSigner(), parameters.getSigBytes());
    }

    public void testSnova()
    {
        SnovaParameters parameters = SnovaParameters.SNOVA_37_17_2_SSK;
        SnovaKeyPairGenerator kpGen = new SnovaKeyPairGenerator();
        kpGen.init(new SnovaKeyGenerationParameters(new SecureRandom(), parameters));

        int sigBytes = ((parameters.getN() * parameters.getLsq() + 1) >>> 1) + parameters.getSaltLength();

        checkBareSignature("SNOVA", kpGen, new SnovaSigner(), new SnovaSigner(), sigBytes);
    }

    public void testQRUOV()
    {
        QRUOVParameters parameters = QRUOVParameters.qruov_1_q127_L3_v156_m54_shake;
        QRUOVKeyPairGenerator kpGen = new QRUOVKeyPairGenerator();
        kpGen.init(new QRUOVKeyGenerationParameters(new SecureRandom(), parameters));

        checkBareSignature("QR-UOV", kpGen, new QRUOVSigner(), new QRUOVSigner(), parameters.getSignatureBytes());
    }

    public void testSQIsign()
    {
        SQIsignParameters parameters = SQIsignParameters.sqisign_lvl1;
        SQIsignKeyPairGenerator kpGen = new SQIsignKeyPairGenerator();
        kpGen.init(new SQIsignKeyGenerationParameters(new SecureRandom(), parameters));

        checkBareSignature("SQIsign", kpGen, new SQIsignSigner(), new SQIsignSigner(), parameters.getSignatureLength());
    }

    public void testAIMer()
    {
        AIMerParameters parameters = AIMerParameters.aimer128f;
        AIMerKeyPairGenerator kpGen = new AIMerKeyPairGenerator();
        kpGen.init(new AIMerKeyGenerationParameters(new SecureRandom(), parameters));

        checkBareSignature("AIMer", kpGen, new AIMerSigner(), new AIMerSigner(), parameters.getSignatureBytes());
    }

    private void checkBareSignature(String name, AsymmetricCipherKeyPairGenerator kpGen,
                                    MessageSigner signer, MessageSigner verifier, int sigBytes)
    {
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new SecureRandom()));
        byte[] signature = signer.generateSignature(MESSAGE);

        verifier.init(false, kp.getPublic());

        assertEquals(name + ": the message must not be part of the signature", sigBytes, signature.length);
        assertTrue(name + ": signature must verify", verifier.verifySignature(MESSAGE, signature));

        // the two signed-message envelopes these schemes used to emit
        assertFalse(name + ": signature || message must not verify",
            verifier.verifySignature(MESSAGE, Arrays.concatenate(signature, MESSAGE)));
        assertFalse(name + ": message || signature must not verify",
            verifier.verifySignature(MESSAGE, Arrays.concatenate(MESSAGE, signature)));

        // trailing data must not be ignored, whatever it is
        assertFalse(name + ": signature with a byte appended must not verify",
            verifier.verifySignature(MESSAGE, Arrays.append(signature, (byte)0)));
        assertFalse(name + ": signature with padding appended must not verify",
            verifier.verifySignature(MESSAGE, Arrays.concatenate(signature, new byte[64])));

        // and a short buffer must be reported rather than indexed past its end
        assertFalse(name + ": truncated signature must not verify",
            verifier.verifySignature(MESSAGE, Arrays.copyOf(signature, signature.length - 1)));
        assertFalse(name + ": empty signature must not verify",
            verifier.verifySignature(MESSAGE, new byte[0]));
    }
}
