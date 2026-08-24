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

    /**
     * Requiring the signature to be exactly the right length pins down what follows it, but not
     * bits inside it that the decoder never reads. For a SNOVA parameter set whose solution is an
     * odd number of GF(16) nibbles, the last byte of the solution carries one nibble and the top
     * four bits are spare - sixteen byte strings used to verify for one signature.
     */
    public void testSnovaUnusedNibbleMustBeZero()
    {
        // n * l^2 = 33 * 9 = 297, odd. SNOVA_24_5_4 (29 * 16 = 464) has no spare nibble.
        SnovaParameters parameters = SnovaParameters.SNOVA_25_8_3_SSK;
        SnovaKeyPairGenerator kpGen = new SnovaKeyPairGenerator();
        kpGen.init(new SnovaKeyGenerationParameters(new SecureRandom(), parameters));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        int sigNibbles = parameters.getN() * parameters.getLsq();
        assertTrue("parameter set must have a spare nibble to test", (sigNibbles & 1) != 0);
        int lastBodyByte = ((sigNibbles + 1) >>> 1) - 1;

        SnovaSigner signer = new SnovaSigner();
        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new SecureRandom()));
        byte[] signature = signer.generateSignature(MESSAGE);

        SnovaSigner verifier = new SnovaSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("SNOVA: signature must verify", verifier.verifySignature(MESSAGE, signature));
        assertEquals("SNOVA: the signer must leave the spare nibble zero",
            0, signature[lastBodyByte] & 0xF0);

        for (int nibble = 1; nibble < 16; nibble++)
        {
            byte[] tampered = Arrays.clone(signature);
            tampered[lastBodyByte] = (byte)((tampered[lastBodyByte] & 0x0F) | (nibble << 4));

            verifier.init(false, kp.getPublic());
            assertFalse("SNOVA: a set spare nibble (" + nibble + ") must not verify",
                verifier.verifySignature(MESSAGE, tampered));
        }
    }

    /**
     * QR-UOV stores each F_q element in ceil(log2 q) bits, one more bit pattern than the field has
     * elements: q itself is representable and is congruent to zero, so every zero element of a
     * signature had a second encoding that verified. The bits padding the last element out to the
     * byte boundary were not read either. For the q = 7 sets that is on the order of a hundred
     * spare bits in a single signature.
     */
    public void testQRUOVSignatureMustBeCanonical()
    {
        QRUOVParameters parameters = QRUOVParameters.qruov_1_q31_L3_v165_m60_shake;
        QRUOVKeyPairGenerator kpGen = new QRUOVKeyPairGenerator();
        kpGen.init(new QRUOVKeyGenerationParameters(new SecureRandom(), parameters));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        QRUOVSigner signer = new QRUOVSigner();
        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new SecureRandom()));

        int q = parameters.getQ();
        int elementBits = parameters.getCeilLog2Q();
        int elements = parameters.getBigN() * parameters.getL();
        int firstElementBit = parameters.getSaltLen() * 8;
        int padBits = parameters.getSignatureBytes() * 8 - (firstElementBit + elements * elementBits);

        QRUOVSigner verifier = new QRUOVSigner();

        // a zero element re-encoded as q must not verify; retry because whether a signature has a
        // zero element at all is chance (about 1 in q per element, so all but certain here)
        boolean testedAnElement = false;
        for (int attempt = 0; attempt < 8 && !testedAnElement; attempt++)
        {
            byte[] signature = signer.generateSignature(MESSAGE);

            verifier.init(false, kp.getPublic());
            assertTrue("QR-UOV: signature must verify", verifier.verifySignature(MESSAGE, signature));

            if (padBits > 0)
            {
                assertEquals("QR-UOV: the signer must leave the padding bits zero",
                    0, (signature[signature.length - 1] & 0xFF) >>> (8 - padBits));

                for (int bit = 8 - padBits; bit < 8; bit++)
                {
                    byte[] tampered = Arrays.clone(signature);
                    tampered[tampered.length - 1] ^= (byte)(1 << bit);

                    verifier.init(false, kp.getPublic());
                    assertFalse("QR-UOV: a set padding bit (" + bit + ") must not verify",
                        verifier.verifySignature(MESSAGE, tampered));
                }
            }

            for (int i = 0; i < elements; i++)
            {
                int bitOff = firstElementBit + i * elementBits;
                if (readBits(signature, bitOff, elementBits) != 0)
                {
                    continue;
                }

                byte[] tampered = Arrays.clone(signature);
                writeBits(tampered, bitOff, elementBits, q);

                verifier.init(false, kp.getPublic());
                assertFalse("QR-UOV: element " + i + " encoded as q must not verify",
                    verifier.verifySignature(MESSAGE, tampered));
                testedAnElement = true;
                break;
            }
        }
        assertTrue("QR-UOV: no zero element turned up to re-encode as q", testedAnElement);
    }

    private static int readBits(byte[] buf, int bitOff, int numBits)
    {
        int shift = bitOff & 7;
        int index = bitOff >>> 3;
        int x = (buf[index] & 0xFF) | (((shift + numBits > 8) ? (buf[index + 1] & 0xFF) : 0) << 8);
        return (x >>> shift) & ((1 << numBits) - 1);
    }

    private static void writeBits(byte[] buf, int bitOff, int numBits, int value)
    {
        int shift = bitOff & 7;
        int index = bitOff >>> 3;
        int mask = ((1 << numBits) - 1) << shift;
        int x = (buf[index] & 0xFF) | (((shift + numBits > 8) ? (buf[index + 1] & 0xFF) : 0) << 8);
        x = (x & ~mask) | ((value << shift) & mask);
        buf[index] = (byte)(x & 0xFF);
        if (shift + numBits > 8)
        {
            buf[index + 1] = (byte)((x >>> 8) & 0xFF);
        }
    }
}
