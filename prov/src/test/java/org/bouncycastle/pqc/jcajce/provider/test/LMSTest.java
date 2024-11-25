package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

/**
 * LMS is now promoted to the BC provider.
 */
public class LMSTest
    extends TestCase
{
    private static final byte[] nestedPublicKey = Base64.decode("MFAwDQYLKoZIhvcNAQkQAxEDPwAEPAAAAAEAAAAFAAAAAa3sRFhG3xQtT/xfuJJswgV80jvx/sFlYxteNrZ0hheITiUL/bJ8wJpphIpoSB/E9g==");
    private static final byte[] nestedPrivateKey = Base64.decode("MIG6AgEBMA0GCyqGSIb3DQEJEAMRBGcEZQAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAUAAAABrexEWEbfFC1P/F+4kmzCBQAAAAAAAAAgAAAAIO01yI+Hj7eX+P2clcPDW0SzllJ4uzQt1JenbcllHpQngT0AAAAAAQAAAAUAAAABrexEWEbfFC1P/F+4kmzCBXzSO/H+wWVjG142tnSGF4hOJQv9snzAmmmEimhIH8T2");

    private static byte[] lmsPublicEnc = Base64.decode("MFAwDQYLKoZIhvcNAQkQAxEDPwAEPAAAAAEAAAAFAAAAAXjGRFXZMjGgOKA/sHWwYWNl6eTf5nI+RcEvlnIKQHQXpxNDreZCkeFm6x9CBN4YlA==");
    private static byte[] lmsPrivateEnc = Base64.decode("MIGhAgEBMA0GCyqGSIb3DQEJEAMRBE4ETAAAAAEAAAAAAAAABQAAAAF4xkRV2TIxoDigP7B1sGFjAAAAAAAAACAAAAAghIRA7xa5TChn4+0KIh1LvGLp14alEkmcz3m3v7kTiBeBPQAAAAABAAAABQAAAAF4xkRV2TIxoDigP7B1sGFjZenk3+ZyPkXBL5ZyCkB0F6cTQ63mQpHhZusfQgTeGJQ=");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testLmsOldKeyEncoding()
        throws Exception
    {
        PKCS8EncodedKeySpec lmsPrivateKeySpec = new PKCS8EncodedKeySpec(lmsPrivateEnc);
        X509EncodedKeySpec lmsPublicKeySpec = new X509EncodedKeySpec(lmsPublicEnc);

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        PrivateKey lmsPrivateKey = kFact.generatePrivate(lmsPrivateKeySpec);
        PublicKey lmsPublicKey = kFact.generatePublic(lmsPublicKeySpec);

        trySigning(new KeyPair(lmsPublicKey, lmsPrivateKey));
    }

    public void testKeyPairGenerators()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        KeyPair kp = kpGen.generateKeyPair();

        trySigning(kp);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        kp = kpGen.generateKeyPair();

        trySigning(kp);

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        kp = kpGen.generateKeyPair();

        trySigning(kp);
    }

    private void trySigning(KeyPair keyPair)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        Signature signer = Signature.getInstance("LMS", "BC");

        signer.initSign(keyPair.getPrivate(), new SecureRandom());

        signer.update(msg);

        byte[] sig = signer.sign();

        signer.initVerify(keyPair.getPublic());

        signer.update(msg);

        assertTrue(signer.verify(sig));
    }

    public void testKeyEncoding()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("LMS", "BC");

        PublicKey oldLmsPub = kf.generatePublic(new X509EncodedKeySpec(nestedPublicKey));
        PrivateKey oldLmsPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(nestedPrivateKey));

        trySigning(new KeyPair(oldLmsPub, oldLmsPriv));

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp = kpGen.generateKeyPair();

        PublicKey newLmsPub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey newLmsPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        trySigning(new KeyPair(newLmsPub, newLmsPriv));
    }

    public void testKeyFactoryLMSKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pub1.getEncoded()));

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), "BC");

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    public void testPublicKeyEncodingLength()
        throws Exception
    {
        KeyPairGenerator kpGen1 = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen1.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp1 = kpGen1.generateKeyPair();

        KeyPairGenerator kpGen2 = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen2.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        KeyPair kp2 = kpGen2.generateKeyPair();

        assertEquals(kp1.getPublic().getEncoded().length, kp2.getPublic().getEncoded().length);
    }

    public void testKeyFactoryHSSKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
        
        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), "BC");

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    public void testKeyGenAndSignTwoSigsWithShardHSS()
        throws Exception
    {
        byte[] msg1 = Strings.toByteArray("Hello, world!");
        byte[] msg2 = Strings.toByteArray("Now is the time");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(
            new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        LMSPrivateKey privKey = ((LMSPrivateKey)kp.getPrivate()).extractKeyShard(2);

        assertEquals(2,  ((LMSPrivateKey)kp.getPrivate()).getIndex());

        assertEquals(2, privKey.getUsagesRemaining());
        assertEquals(0, privKey.getIndex());

        Signature signer = Signature.getInstance("LMS", "BC");

        signer.initSign(privKey);

        signer.update(msg1);

        byte[] sig1 = signer.sign();

        assertEquals(1, privKey.getIndex());

        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig1));

        signer.initSign(privKey);

        signer.update(msg2);

        byte[] sig2 = signer.sign();

        assertEquals(0, privKey.getUsagesRemaining());

        try
        {
            signer.update(msg2);

            fail("no exception");
        }
        catch (SignatureException e)
        {
            assertEquals("hss private key shard is exhausted", e.getMessage());
        }

        signer = Signature.getInstance("LMS", "BC");

        signer.initVerify(kp.getPublic());

        signer.update(msg2);

        assertTrue(signer.verify(sig2));
  
        try
        {
            signer.initSign(privKey);
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("private key exhausted", e.getMessage());
        }

        assertEquals(2,  ((LMSPrivateKey)kp.getPrivate()).getIndex());

        signer.initSign(kp.getPrivate());

        signer.update(msg1);

        byte[] sig = signer.sign();
        
        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig));
        assertFalse(Arrays.areEqual(sig1, sig));
        assertEquals(3,  ((LMSPrivateKey)kp.getPrivate()).getIndex());
    }
}
