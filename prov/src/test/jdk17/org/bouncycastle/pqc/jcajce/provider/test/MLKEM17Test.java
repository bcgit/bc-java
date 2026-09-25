package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

public class MLKEM17Test
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKEM()
            throws Exception
    {
        // Receiver side
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC");

        g.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        KeyPair kp = g.generateKeyPair();
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("ML-KEM", "BC");
        KTSParameterSpec ktsSpec = null;
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();
        byte[] params = enc.params();

        // Receiver side
        KEM kemR = KEM.getInstance("ML-KEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsSpec);
        SecretKey secR = d.decapsulate(em);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    /**
     * javax.crypto.KEM bound to BC accepts ML-KEM keys from another provider, converting them from their encodings.
     */
    public void testKEMForeignKeys()
            throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC");

        g.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        KeyPair kp = g.generateKeyPair();

        PublicKey fPub = new MLKEMTest.ForeignPublicKey(kp.getPublic().getEncoded());
        PrivateKey fPriv = new MLKEMTest.ForeignPrivateKey(kp.getPrivate().getEncoded());

        String[] kemNames = { "ML-KEM", "ML-KEM-768" };
        for (int i = 0; i != kemNames.length; i++)
        {
            KEM kem = KEM.getInstance(kemNames[i], "BC");

            KEM.Encapsulated enc = kem.newEncapsulator(fPub).encapsulate();
            SecretKey secR = kem.newDecapsulator(fPriv).decapsulate(enc.encapsulation());

            assertTrue(Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));
        }

        try
        {
            KEM.getInstance("ML-KEM-512", "BC").newEncapsulator(fPub);
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("ML-KEM key mismatch", e.getMessage());
        }

        try
        {
            KEM.getInstance("ML-KEM", "BC").newDecapsulator(new MLKEMTest.ForeignPrivateKey(null));
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("unsupported key type", e.getMessage());
        }
    }

    public void testBasicKEMAES()
            throws Exception
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("AES"));
        performKEM(kpg.generateKeyPair(),0, 16, "AES", new KEMParameterSpec("AES"));
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("AES-KWP"));

        try
        {
            performKEM(kpg.generateKeyPair(),0, 16, "AES-KWP", new KEMParameterSpec("AES"));
            fail();
        }
        catch (Exception ex)
        {
        }

        kpg.initialize(MLKEMParameterSpec.ml_kem_1024, new SecureRandom());
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("AES"));



    }

    public void testBasicKEMCamellia()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
    }

    public void testBasicKEMSEED()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("SEED", 128).build());
    }

    public void testBasicKEMARIA()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("ARIA"));
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("ARIA-KWP"));
    }

    private void performKEM(KeyPair kp, int from, int to, String algorithm, KTSParameterSpec ktsParameterSpec)
            throws Exception
    {
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("ML-KEM", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate(from, to, algorithm);
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        // Receiver side
        KEM kemR = KEM.getInstance("ML-KEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(em, from, to, algorithm);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    private void performKEM(KeyPair kp, KTSParameterSpec ktsParameterSpec)
            throws Exception
    {
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("ML-KEM", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        // Receiver side
        KEM kemR = KEM.getInstance("ML-KEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(em);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }
}
