package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.faest.FaestKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.faest.FaestKeyPairGenerator;
import org.bouncycastle.pqc.crypto.faest.FaestParameters;
import org.bouncycastle.pqc.crypto.faest.FaestPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.faest.FaestPublicKeyParameters;
import org.bouncycastle.pqc.crypto.faest.FaestSigner;

/**
 * Round-trip test for {@link FaestKeyPairGenerator} + {@link FaestSigner}.
 * Generates a key pair, signs a message with the private key + injected
 * SecureRandom, then verifies with the public key. Also confirms a tampered
 * message and tampered signature both reject.
 */
public class FaestKeyPairAndSignerTest
    extends TestCase
{
    public void testFaest128s()
    {
        roundtrip(FaestParameters.faest_128s);
    }

    public void testFaestEm192s()
    {
        roundtrip(FaestParameters.faest_em_192s);
    }

    private void roundtrip(FaestParameters p)
    {
        SecureRandom rng = new SecureRandom();

        FaestKeyPairGenerator kpg = new FaestKeyPairGenerator();
        kpg.init(new FaestKeyGenerationParameters(rng, p));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        FaestPublicKeyParameters pub = (FaestPublicKeyParameters)kp.getPublic();
        FaestPrivateKeyParameters priv = (FaestPrivateKeyParameters)kp.getPrivate();

        assertEquals("pk length", p.getPkSize(), pub.getEncoded().length);
        assertEquals("sk length", p.getSkSize(), priv.getEncoded().length);

        // sk and pk share the OWF input (first owfInputSize bytes).
        byte[] pkEnc = pub.getEncoded();
        byte[] skEnc = priv.getEncoded();
        for (int i = 0; i < p.getOwfInputSize(); i++)
        {
            assertEquals("pk/sk owfInput byte " + i, pkEnc[i], skEnc[i]);
        }

        byte[] msg = "FAEST round-trip test message".getBytes();

        FaestSigner signer = new FaestSigner();
        signer.init(true, new ParametersWithRandom(priv, rng));
        byte[] sig = signer.generateSignature(msg);
        assertEquals("signature length", p.getSigSize(), sig.length);

        FaestSigner verifier = new FaestSigner();
        verifier.init(false, pub);
        assertTrue(p.getName() + " good signature accepted", verifier.verifySignature(msg, sig));

        // Tamper with the message: should reject.
        byte[] tamp = msg.clone();
        tamp[0] ^= 1;
        assertFalse(p.getName() + " tampered message rejected", verifier.verifySignature(tamp, sig));

        // Tamper with the signature: should reject.
        byte[] sigTamp = sig.clone();
        sigTamp[0] ^= 1;
        assertFalse(p.getName() + " tampered signature rejected", verifier.verifySignature(msg, sigTamp));
    }
}
