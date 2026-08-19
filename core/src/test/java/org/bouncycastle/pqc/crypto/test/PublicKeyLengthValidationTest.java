package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKEMExtractor;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPublicKeyParameters;

/**
 * Regression test for the PQC public-key length-validation hardening (finding #14).
 * <p>
 * ML-DSA and Falcon public-key parameter classes must reject a malformed-length encoding with an
 * <code>IllegalArgumentException</code> at decode time, rather than storing it and throwing an
 * <code>ArrayIndexOutOfBoundsException</code> later during signature verification. The crash was a
 * denial of service reachable when verifying with an attacker-supplied key (e.g. a malformed ML-DSA
 * certificate exercised during certification-path validation). This mirrors the ML-KEM / SLH-DSA
 * parameter classes, which already validate the encoding length.
 * <p>
 * Each negative case is constructed from a 33-byte buffer: long enough that the old ML-DSA code
 * accepted it (splitting off a 1-byte <code>t1</code>), short enough that <code>Packing</code> then
 * indexed past it (<code>arraycopy: length -319 is negative</code>) at verify time.
 */
public class PublicKeyLengthValidationTest
    extends TestCase
{
    private static final byte[] SHORT_ENCODING = new byte[33];

    // ML-DSA-44 public key is SeedBytes + k*DilithiumPolyT1PackedBytes = 32 + 4*320 = 1312 bytes.
    public void testMLDSAPublicKeyRejectsMalformedLength()
    {
        try
        {
            new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, SHORT_ENCODING);
            fail("expected IllegalArgumentException for short ML-DSA public key (crypto.params)");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'encoding' has invalid length", e.getMessage());
        }
    }

    // Control: ML-KEM already validated its encoding length; this pins the message contract that
    // the ML-DSA fix is brought in line with.
    public void testMLKEMPublicKeyRejectsMalformedLength()
    {
        try
        {
            new org.bouncycastle.crypto.params.MLKEMPublicKeyParameters(
                org.bouncycastle.crypto.params.MLKEMParameters.ml_kem_512, SHORT_ENCODING);
            fail("expected IllegalArgumentException for short ML-KEM public key (crypto.params)");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'encoding' has invalid length", e.getMessage());
        }

        try
        {
            new org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters(
                org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters.ml_kem_512, SHORT_ENCODING);
            fail("expected IllegalArgumentException for short ML-KEM public key (pqc.crypto.mlkem)");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'encoding' has invalid length", e.getMessage());
        }
    }

    public void testFalconPublicKeyRejectsMalformedLength()
    {
        try
        {
            new FalconPublicKeyParameters(FalconParameters.falcon_512, SHORT_ENCODING);
            fail("expected IllegalArgumentException for short Falcon public key");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'H' has invalid length", e.getMessage());
        }
    }

    // The original denial of service: a valid signature verified against a malformed public key
    // crashed verifyInternal with ArrayIndexOutOfBoundsException. With the decode-time guard the
    // malformed key can no longer be constructed, so the crash path is unreachable, while a
    // well-formed key (reconstructed from its own encoding) still verifies.
    public void testMLDSAValidKeyVerifiesAndMalformedKeyIsRejected()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        MLDSAKeyPairGenerator kpg = new MLDSAKeyPairGenerator();
        kpg.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_44));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        byte[] msg = new byte[64];
        random.nextBytes(msg);

        MLDSASigner signer = new MLDSASigner();
        signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
        signer.update(msg, 0, msg.length);
        byte[] signature = signer.generateSignature();

        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters)kp.getPublic();
        MLDSAPublicKeyParameters rebuilt = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, pub.getEncoded());

        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, rebuilt);
        verifier.update(msg, 0, msg.length);
        assertTrue("a well-formed ML-DSA-44 signature must still verify", verifier.verifySignature(signature));

        try
        {
            new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, SHORT_ENCODING);
            fail("expected IllegalArgumentException for short ML-DSA public key");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'encoding' has invalid length", e.getMessage());
        }
    }

    /**
     * SMAUG-T: both key-decode constructors stored the encoding unchecked, so a malformed-length key
     * was accepted silently and only crashed later - the public key with an
     * <code>ArrayIndexOutOfBoundsException</code> inside encapsulation, the private key with garbage
     * behaviour at decapsulation time. Both are reachable from untrusted input via
     * <code>PublicKeyFactory</code> (SubjectPublicKeyInfo) and <code>PrivateKeyFactory</code> (PKCS#8).
     */
    public void testSmaugTPublicKeyRejectsMalformedLength()
    {
        SmaugTParameters[] sets = new SmaugTParameters[]
            {
                SmaugTParameters.smaugt_mode1, SmaugTParameters.smaugt_mode3,
                SmaugTParameters.smaugt_mode5, SmaugTParameters.smaugt_modet
            };

        for (int i = 0; i != sets.length; i++)
        {
            try
            {
                new SmaugTPublicKeyParameters(sets[i], SHORT_ENCODING);
                fail("expected IllegalArgumentException for short SMAUG-T public key: " + sets[i].getName());
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("'publicKey' has invalid length", e.getMessage());
            }
        }
    }

    public void testSmaugTPrivateKeyRejectsMalformedLength()
    {
        SmaugTParameters[] sets = new SmaugTParameters[]
            {
                SmaugTParameters.smaugt_mode1, SmaugTParameters.smaugt_mode3,
                SmaugTParameters.smaugt_mode5, SmaugTParameters.smaugt_modet
            };

        for (int i = 0; i != sets.length; i++)
        {
            try
            {
                new SmaugTPrivateKeyParameters(sets[i], SHORT_ENCODING);
                fail("expected IllegalArgumentException for short SMAUG-T private key: " + sets[i].getName());
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("'privateKey' has invalid length", e.getMessage());
            }
        }
    }

    /**
     * SMAUG-T decapsulation indexed the ciphertext at fixed offsets up to CIPHERTEXT_BYTES with no
     * length check, so a short encapsulation threw an <code>ArrayIndexOutOfBoundsException</code> out
     * of <code>extractSecret</code>. Mirrors the HQC / NTRU Prime / BIKE extractors.
     */
    public void testSmaugTExtractorRejectsWrongLengthEncapsulation()
    {
        SmaugTKeyPairGenerator kpg = new SmaugTKeyPairGenerator();
        kpg.init(new SmaugTKeyGenerationParameters(new SecureRandom(), SmaugTParameters.smaugt_mode1));

        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        SmaugTKEMExtractor extractor = new SmaugTKEMExtractor((SmaugTPrivateKeyParameters)kp.getPrivate());

        int expected = extractor.getEncapsulationLength();

        int[] wrong = new int[]{0, 1, expected - 1, expected + 1};
        for (int i = 0; i != wrong.length; i++)
        {
            try
            {
                extractor.extractSecret(new byte[wrong[i]]);
                fail("expected IllegalArgumentException for encapsulation length " + wrong[i]);
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("encapsulation wrong length", e.getMessage());
            }
        }

        // control: the correct length is still accepted and yields a shared secret
        byte[] ok = extractor.extractSecret(new byte[expected]);
        assertEquals(32, ok.length);
    }
}
