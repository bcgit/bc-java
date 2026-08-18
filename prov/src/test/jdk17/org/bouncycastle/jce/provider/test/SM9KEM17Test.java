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
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
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

        byte[] bobIdentity = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobIdentity, SM9EncMasterPrivateKeyParameters.HID);

        // Sender side - the recipient public key comes from the published master public key
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobIdentity);

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

        byte[] bobIdentity = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobIdentity, SM9EncMasterPrivateKeyParameters.HID);
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobIdentity);

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

        byte[] bobIdentity = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobIdentity, SM9EncMasterPrivateKeyParameters.HID);
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobIdentity);

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
        byte[] bobIdentity = Strings.toByteArray("Bob");
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobIdentity);
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

        // a spec with no key algorithm name is refused at construction - SM9 does not go
        // through KdfUtil.resolveKemSpec, so it carries this check itself; without it the null
        // is substituted for a "Generic" request and fails deep inside the derivation
        KTSParameterSpec nullName = new KTSParameterSpec.Builder(null, 256).withNoKdf().build();
        try
        {
            kem.newEncapsulator(bobPublic, nullName, null);
            fail("encapsulator accepted a spec with no key algorithm name");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        try
        {
            kem.newDecapsulator(((SM9EncMasterPrivateKey)master.getPrivate())
                .generateUserKeyPair(bobIdentity, SM9EncMasterPrivateKeyParameters.HID).getPrivate(), nullName);
            fail("decapsulator accepted a spec with no key algorithm name");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }
    }

    /**
     * The spec/algorithm reconciliation - "Generic" on either side deferring to the other, and a
     * genuine mismatch being refused - is shared with every other KEM, but nothing here reached it:
     * testKEM passes a null spec, so both sides are "Generic" and agree whatever the rule does.
     */
    public void testAlgorithmReconciliation()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        KeyPair master = g.generateKeyPair();

        byte[] bobIdentity = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobIdentity, SM9EncMasterPrivateKeyParameters.HID);
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobIdentity);

        KTSParameterSpec aes = new KTSParameterSpec.Builder("AES", 128).withNoKdf().build();

        // a "Generic" request takes the spec's name, on both sides
        KEM.Encapsulator e = KEM.getInstance("SM9-KEM", "BC").newEncapsulator(bobPublic, aes, null);
        KEM.Encapsulated enc = e.encapsulate();
        assertEquals("AES", enc.key().getAlgorithm());

        KEM.Decapsulator d = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(bob.getPrivate(), aes);
        SecretKey secR = d.decapsulate(enc.encapsulation());
        assertEquals("AES", secR.getAlgorithm());
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));

        // and a name the spec does not authorise is refused, on both sides
        try
        {
            e.encapsulate(0, 16, "AES-KWP");
            fail("encapsulator accepted an algorithm its spec does not name");
        }
        catch (UnsupportedOperationException expected)
        {
            assertEquals("AES does not match AES-KWP", expected.getMessage());
        }

        try
        {
            d.decapsulate(enc.encapsulation(), 0, 16, "AES-KWP");
            fail("decapsulator accepted an algorithm its spec does not name");
        }
        catch (UnsupportedOperationException expected)
        {
            assertEquals("AES does not match AES-KWP", expected.getMessage());
        }
    }
}
