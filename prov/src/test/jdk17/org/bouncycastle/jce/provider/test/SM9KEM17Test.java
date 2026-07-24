package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEM;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * javax.crypto.KEM API tests for the SM9 identity-based KEM ({@code KEM.SM9-KEM}).
 */
public class SM9KEM17Test
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
        // KGC side
        KeyPairGenerator g = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair master = g.generateKeyPair();

        byte[] bobId = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobId);

        // Sender side - the recipient public key comes from the published master public key
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobId);

        KEM kemS = KEM.getInstance("SM9-KEM", "BC");
        KTSParameterSpec ktsSpec = null;
        KEM.Encapsulator e = kemS.newEncapsulator(bobPublic, ktsSpec, null);
        assertEquals(32, e.secretSize());
        assertEquals(64, e.encapsulationSize());
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        // Receiver side
        KEM kemR = KEM.getInstance("SM9-KEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(bob.getPrivate(), ktsSpec);
        SecretKey secR = d.decapsulate(em);

        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    public void testNoKdfMatchesKeyGeneratorBridge()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair master = g.generateKeyPair();

        byte[] bobId = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobId);
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobId);

        // KEM API, no KDF: the secret is SM9's own GM/T 0044.4 KDF output
        KTSParameterSpec noKdf = new KTSParameterSpec.Builder("AES", 128).withNoKdf().build();
        KEM.Encapsulator e = KEM.getInstance("SM9-KEM", "BC").newEncapsulator(bobPublic, noKdf, null);
        KEM.Encapsulated enc = e.encapsulate();
        assertEquals(16, enc.key().getEncoded().length);

        // ... so the KeyGenerator bridge recovers the identical key from the same encapsulation
        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        decapsulator.init(new KEMExtractSpec(bob.getPrivate(), enc.encapsulation(), "AES", 128));
        SecretKeyWithEncapsulation viaKeyGenerator = (SecretKeyWithEncapsulation)decapsulator.generateKey();

        assertTrue(Arrays.areEqual(enc.key().getEncoded(), viaKeyGenerator.getEncoded()));
    }

    public void testOptionalExternalKdf()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair master = g.generateKeyPair();

        byte[] bobId = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobId);
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobId);

        // default KTSParameterSpec carries a KDF (KDF3/SHA-256) - layered over SM9's output
        KTSParameterSpec withKdf = new KTSParameterSpec.Builder("AES", 128).build();
        KEM.Encapsulator e = KEM.getInstance("SM9-KEM", "BC").newEncapsulator(bobPublic, withKdf, null);
        KEM.Encapsulated enc = e.encapsulate();

        KEM.Decapsulator d = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(bob.getPrivate(), withKdf);
        SecretKey secR = d.decapsulate(enc.encapsulation());
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));

        // decapsulating the same encapsulation without the KDF must give a different key
        // (the external KDF is not the GM/T 0044.4 interoperable form)
        KTSParameterSpec noKdf = new KTSParameterSpec.Builder("AES", 128).withNoKdf().build();
        KEM.Decapsulator dRaw = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(bob.getPrivate(), noKdf);
        SecretKey raw = dRaw.decapsulate(enc.encapsulation());
        assertFalse(Arrays.areEqual(enc.key().getEncoded(), raw.getEncoded()));
    }

    public void testGuards()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair master = g.generateKeyPair();

        KEM kem = KEM.getInstance("SM9-KEM", "BC");

        // a master public key is not a recipient key
        try
        {
            kem.newEncapsulator(master.getPublic(), null, null);
            fail("encapsulator accepted a non-recipient key");
        }
        catch (InvalidKeyException expected)
        {
        }

        // only KTSParameterSpec is understood
        byte[] bobId = Strings.toByteArray("Bob");
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobId);
        try
        {
            kem.newEncapsulator(bobPublic, new AlgorithmParameterSpec()
            {
            }, null);
            fail("encapsulator accepted a foreign spec");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }
    }
}
