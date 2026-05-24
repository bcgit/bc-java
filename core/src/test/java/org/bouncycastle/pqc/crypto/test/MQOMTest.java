package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMSigner;
import org.bouncycastle.util.test.FixedSecureRandom;

public class MQOMTest
    extends TestCase
{
    public void testParameterSizes()
    {
        MQOMParameters p = MQOMParameters.mqom2_cat1_gf256_fast_r3;
        assertEquals(80, p.getPublicKeySize());
        assertEquals(128, p.getPrivateKeySize());
        assertEquals(4164, p.getSignatureSize());
        assertEquals(16, p.getSeedSize());
        assertEquals(16, p.getSaltSize());
        assertEquals(32, p.getDigestSize());
        assertEquals(48, p.getMqN());
        assertEquals(17, p.getTau());
        assertEquals(256, p.getNbEvals());
    }

    public void testKeyGenDeterministic()
    {
        MQOMParameters params = MQOMParameters.mqom2_cat1_gf256_fast_r3;

        // MQOMKeyPairGenerator draws 2*seedSize bytes from its SecureRandom.
        // Feeding the same bytes through two FixedSecureRandoms must produce
        // identical key pairs.
        byte[] seedKey = new byte[2 * params.getSeedSize()];
        for (int i = 0; i < seedKey.length; i++)
        {
            seedKey[i] = (byte)i;
        }

        AsymmetricCipherKeyPair kp1 = generateKeyPair(params, new FixedSecureRandom(seedKey));
        AsymmetricCipherKeyPair kp2 = generateKeyPair(params, new FixedSecureRandom(seedKey));

        byte[] pk1 = ((MQOMPublicKeyParameters)kp1.getPublic()).getEncoded();
        byte[] sk1 = ((MQOMPrivateKeyParameters)kp1.getPrivate()).getEncoded();
        byte[] pk2 = ((MQOMPublicKeyParameters)kp2.getPublic()).getEncoded();
        byte[] sk2 = ((MQOMPrivateKeyParameters)kp2.getPrivate()).getEncoded();

        for (int i = 0; i < pk1.length; i++)
        {
            assertEquals("pk byte " + i, pk1[i], pk2[i]);
        }
        for (int i = 0; i < sk1.length; i++)
        {
            assertEquals("sk byte " + i, sk1[i], sk2[i]);
        }
        // MQOM's secret-key layout starts with the same pk_seed-derived bytes
        // as the public key; this invariant is what the byte-by-byte check
        // below records.
        for (int i = 0; i < pk1.length; i++)
        {
            assertEquals("sk[i] vs pk[i] " + i, pk1[i], sk1[i]);
        }
    }

    public void testSignVerifyRoundTrip()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        MQOMParameters parameters = MQOMParameters.mqom2_cat1_gf256_fast_r3;

        MQOMKeyPairGenerator kpg = new MQOMKeyPairGenerator();
        kpg.init(new MQOMKeyGenerationParameters(random, parameters));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        byte[] msg = "MQOM round trip test message".getBytes("UTF-8");

        MQOMSigner signer = new MQOMSigner();
        signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
        byte[] sig = signer.generateSignature(msg);

        assertEquals(parameters.getSignatureSize(), sig.length);

        signer.init(false, kp.getPublic());
        assertTrue("verify should succeed", signer.verifySignature(msg, sig));

        byte[] wrong = "different message".getBytes("UTF-8");
        signer.init(false, kp.getPublic());
        assertFalse("verify should fail on wrong message", signer.verifySignature(wrong, sig));

        byte[] tampered = sig.clone();
        tampered[0] ^= 0x01;
        signer.init(false, kp.getPublic());
        assertFalse("verify should fail on tampered signature", signer.verifySignature(msg, tampered));
    }

    public void testSignVerifyAcrossAllParameterSets()
        throws Exception
    {
        MQOMParameters[] subset = new MQOMParameters[]{
            MQOMParameters.mqom2_cat1_gf2_fast_r3,
            MQOMParameters.mqom2_cat1_gf16_fast_r5,
            MQOMParameters.mqom2_cat1_gf256_short_r3,
            MQOMParameters.mqom2_cat3_gf2_short_r5,
            MQOMParameters.mqom2_cat3_gf16_fast_r3,
            MQOMParameters.mqom2_cat3_gf256_fast_r5,
            MQOMParameters.mqom2_cat5_gf2_short_r3,
            MQOMParameters.mqom2_cat5_gf16_short_r5,
            MQOMParameters.mqom2_cat5_gf256_fast_r3
        };
        SecureRandom random = new SecureRandom();
        byte[] msg = "round trip across variants".getBytes("UTF-8");

        for (int i = 0; i < subset.length; i++)
        {
            MQOMParameters p = subset[i];
            MQOMKeyPairGenerator kpg = new MQOMKeyPairGenerator();
            kpg.init(new MQOMKeyGenerationParameters(random, p));
            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

            MQOMSigner signer = new MQOMSigner();
            signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
            byte[] sig = signer.generateSignature(msg);
            assertEquals(p.getName() + " sig size", p.getSignatureSize(), sig.length);

            signer.init(false, kp.getPublic());
            assertTrue(p.getName() + " verify", signer.verifySignature(msg, sig));
        }
    }

    public void testSignVerifyDeterministicSign()
    {
        MQOMParameters params = MQOMParameters.mqom2_cat1_gf256_fast_r3;

        byte[] seedKey = new byte[2 * params.getSeedSize()];
        for (int i = 0; i < seedKey.length; i++)
        {
            seedKey[i] = (byte)(i + 1);
        }
        AsymmetricCipherKeyPair kp = generateKeyPair(params, new FixedSecureRandom(seedKey));

        // MQOMSigner draws first mseed (seedSize bytes) then salt (saltSize)
        // from the SecureRandom. Concatenating mseed || salt into a
        // FixedSecureRandom reproduces the engine's deterministic signing.
        byte[] mseed = new byte[params.getSeedSize()];
        for (int i = 0; i < mseed.length; i++)
        {
            mseed[i] = (byte)(0xA0 + i);
        }
        byte[] salt = new byte[params.getSaltSize()];
        for (int i = 0; i < salt.length; i++)
        {
            salt[i] = (byte)(0x50 + i);
        }
        byte[] mseedAndSalt = concat(mseed, salt);

        byte[] msg = new byte[]{ 0x01, 0x02, 0x03, 0x04 };

        byte[] sig = sign(kp.getPrivate(), msg, new FixedSecureRandom(mseedAndSalt));
        byte[] sig2 = sign(kp.getPrivate(), msg, new FixedSecureRandom(mseedAndSalt));

        for (int i = 0; i < sig.length; i++)
        {
            assertEquals("deterministic sig byte " + i, sig[i], sig2[i]);
        }

        MQOMSigner verifier = new MQOMSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("verify should succeed", verifier.verifySignature(msg, sig));
    }

    private static AsymmetricCipherKeyPair generateKeyPair(MQOMParameters params, SecureRandom random)
    {
        MQOMKeyPairGenerator kpg = new MQOMKeyPairGenerator();
        kpg.init(new MQOMKeyGenerationParameters(random, params));
        return kpg.generateKeyPair();
    }

    private static byte[] sign(CipherParameters privKey, byte[] msg, SecureRandom random)
    {
        MQOMSigner signer = new MQOMSigner();
        signer.init(true, new ParametersWithRandom(privKey, random));
        return signer.generateSignature(msg);
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
