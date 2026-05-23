package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mqom.MQOMEngine;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMSigner;

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
        byte[] seedKey = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            seedKey[i] = (byte)i;
        }

        MQOMEngine engine = MQOMEngine.getInstance(MQOMParameters.mqom2_cat1_gf256_fast_r3);
        byte[] pk1 = new byte[80];
        byte[] sk1 = new byte[128];
        engine.keyGen(seedKey, sk1, pk1);

        byte[] pk2 = new byte[80];
        byte[] sk2 = new byte[128];
        engine.keyGen(seedKey, sk2, pk2);

        for (int i = 0; i < pk1.length; i++)
        {
            assertEquals("pk byte " + i, pk1[i], pk2[i]);
        }
        for (int i = 0; i < sk1.length; i++)
        {
            assertEquals("sk byte " + i, sk1[i], sk2[i]);
        }
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
        MQOMParameters parameters = MQOMParameters.mqom2_cat1_gf256_fast_r3;
        MQOMEngine engine = MQOMEngine.getInstance(parameters);

        byte[] seedKey = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            seedKey[i] = (byte)(i + 1);
        }
        byte[] pk = new byte[parameters.getPublicKeySize()];
        byte[] sk = new byte[parameters.getPrivateKeySize()];
        engine.keyGen(seedKey, sk, pk);

        byte[] mseed = new byte[parameters.getSeedSize()];
        byte[] salt = new byte[parameters.getSaltSize()];
        for (int i = 0; i < mseed.length; i++)
        {
            mseed[i] = (byte)(0xA0 + i);
        }
        for (int i = 0; i < salt.length; i++)
        {
            salt[i] = (byte)(0x50 + i);
        }

        byte[] msg = new byte[]{ 0x01, 0x02, 0x03, 0x04 };
        byte[] sig = engine.sign(sk, msg, salt, mseed);

        assertTrue("verify should succeed", engine.verify(pk, msg, sig));

        byte[] sig2 = engine.sign(sk, msg, salt, mseed);
        for (int i = 0; i < sig.length; i++)
        {
            assertEquals("deterministic sig byte " + i, sig[i], sig2[i]);
        }
    }
}
