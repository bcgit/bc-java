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
        // new public API (org.bouncycastle.crypto.params)
        try
        {
            new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, SHORT_ENCODING);
            fail("expected IllegalArgumentException for short ML-DSA public key (crypto.params)");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'encoding' has invalid length", e.getMessage());
        }

        // deprecated decode path still used by PublicKeyFactory (org.bouncycastle.pqc.crypto.mldsa)
        try
        {
            new org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters(
                org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters.ml_dsa_44, SHORT_ENCODING);
            fail("expected IllegalArgumentException for short ML-DSA public key (pqc.crypto.mldsa)");
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
}
