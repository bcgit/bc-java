package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

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
    private byte[] bobIdentity;
    private KeyPair masterPair;
    private KeyPair bob;
    private PublicKey bobPublic;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        // KGC side: Bob's key pair from the master private key; sender side: his public key from the
        // published master public key - all made afresh for each test
        bobIdentity = Strings.toByteArray("Bob");
        masterPair = KeyPairGenerator.getInstance("SM9-ENC", "BC").generateKeyPair();
        bob = ((SM9EncMasterPrivateKey)masterPair.getPrivate()).generateUserKeyPair(bobIdentity, SM9EncMasterPrivateKeyParameters.HID);
        bobPublic = ((SM9EncMasterPublicKey)masterPair.getPublic()).getUserPublicKey(bobIdentity);
    }

    public void testKEM()
        throws Exception
    {
        KEM kemS = KEM.getInstance("SM9-KEM", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(bobPublic, null, null);
        assertEquals(32, e.secretSize());
        assertEquals(64, e.encapsulationSize());
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        // Receiver side
        KEM kemR = KEM.getInstance("SM9-KEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(bob.getPrivate(), null);
        SecretKey secR = d.decapsulate(em);

        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    /**
     * The GM/T 0044.5-2016 Annex C vector through javax.crypto.KEM: the default spec takes the
     * mechanism's own KDF output at 256 bits, so an encapsulator handed the vector's r reproduces
     * its K and C, and a decapsulator turns C back into K - which a round trip between two
     * provider objects cannot establish.
     */
    public void testKnownAnswer()
        throws Exception
    {
        java.util.Map v = SM9Vectors.load("sm9_kem.txt");
        byte[] identity = SM9Vectors.hex(v, "IDB");
        byte[] expectedK = SM9Vectors.hex(v, "K");
        byte[] expectedC = Arrays.concatenate(SM9Vectors.hex(v, "C_x"), SM9Vectors.hex(v, "C_y"));
        assertEquals("256", v.get("klen_bits"));

        SM9EncMasterPrivateKeyParameters master =
            new SM9EncMasterPrivateKeyParameters(new java.math.BigInteger((String)v.get("ke"), 16));
        org.bouncycastle.asn1.x509.AlgorithmIdentifier sm9encrypt = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
            org.bouncycastle.asn1.gm.GMObjectIdentifiers.sm9encrypt);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("SM9", "BC");
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(
            new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(sm9encrypt,
                new org.bouncycastle.asn1.DEROctetString(master.getEncoded())).getEncoded()));
        SM9EncMasterPublicKey masterPub = (SM9EncMasterPublicKey)kf.generatePublic(new java.security.spec.X509EncodedKeySpec(
            new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(sm9encrypt,
                master.getPublicKeyParameters().getEncoded()).getEncoded()));

        KEM.Encapsulator e = KEM.getInstance("SM9-KEM", "BC").newEncapsulator(masterPub.getUserPublicKey(identity),
            null, new org.bouncycastle.util.test.TestRandomBigInteger(256, SM9Vectors.hex(v, "r")));
        KEM.Encapsulated enc = e.encapsulate();
        assertTrue("KEM.SM9-KEM reproduces the GM/T 0044.5 K", Arrays.areEqual(expectedK, enc.key().getEncoded()));
        assertTrue("KEM.SM9-KEM reproduces the GM/T 0044.5 C", Arrays.areEqual(expectedC, enc.encapsulation()));

        KEM.Decapsulator d = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(
            masterPriv.generateUserKeyPair(identity, SM9EncMasterPrivateKeyParameters.HID).getPrivate(), null);
        assertTrue("KEM.SM9-KEM decapsulates the GM/T 0044.5 C to K",
            Arrays.areEqual(expectedK, d.decapsulate(expectedC).getEncoded()));
    }

    public void testNoKdfMatchesKeyGeneratorBridge()
        throws Exception
    {
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
        // default KTSParameterSpec carries a KDF (KDF3/SHA-256) - layered over SM9's output
        KTSParameterSpec withKdf = new KTSParameterSpec.Builder("AES", 128).build();
        KEM.Encapsulator e = KEM.getInstance("SM9-KEM", "BC").newEncapsulator(bobPublic, withKdf, null);
        KEM.Encapsulated enc = e.encapsulate();

        KEM.Decapsulator d = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(bob.getPrivate(), withKdf);
        SecretKey secR = d.decapsulate(enc.encapsulation());
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));

        // decapsulating the same encapsulation without the KDF gives a different key (the external KDF
        // is not the GM/T 0044.4 interoperable form)
        KTSParameterSpec noKdf = new KTSParameterSpec.Builder("AES", 128).withNoKdf().build();
        KEM.Decapsulator dRaw = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(bob.getPrivate(), noKdf);
        SecretKey raw = dRaw.decapsulate(enc.encapsulation());
        assertFalse(Arrays.areEqual(enc.key().getEncoded(), raw.getEncoded()));
    }

    /**
     * A destroyed key is refused when the decapsulator is built, rather than taken and left to fail in
     * decapsulate(), whose contract names only DecapsulateException.
     */
    public void testDestroyedKeyRefused()
        throws Exception
    {
        PrivateKey key = bob.getPrivate();
        ((Destroyable)key).destroy();
        try
        {
            KEM.getInstance("SM9-KEM", "BC").newDecapsulator(key);
            fail("decapsulator accepted a destroyed key");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }

    /**
     * A key destroyed after the decapsulator took it makes decapsulate() fail with the
     * DecapsulateException it declares, not the key's IllegalStateException.
     */
    public void testKeyDestroyedAfterDecapsulatorMade()
        throws Exception
    {
        PrivateKey key = bob.getPrivate();
        byte[] encapsulation = KEM.getInstance("SM9-KEM", "BC").newEncapsulator(bobPublic).encapsulate().encapsulation();
        KEM.Decapsulator d = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(key);
        ((Destroyable)key).destroy();
        try
        {
            d.decapsulate(encapsulation);
            fail("decapsulated under a key destroyed after the decapsulator was made");
        }
        catch (DecapsulateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }

    /**
     * An encapsulation of the right length that is not a point of G1 - (1, 1) is not on the curve - is
     * refused with the DecapsulateException decapsulate() declares.
     */
    public void testMalformedEncapsulation()
        throws Exception
    {
        KEM.Decapsulator d = KEM.getInstance("SM9-KEM", "BC").newDecapsulator(bob.getPrivate());
        byte[] offCurve = new byte[64];
        offCurve[31] = 1;
        offCurve[63] = 1;
        try
        {
            d.decapsulate(offCurve);
            fail("decapsulated a point that is not on the curve");
        }
        catch (DecapsulateException e)
        {
            assertEquals("invalid SM9 KEM encapsulation", e.getMessage());
        }
    }

    public void testGuards()
        throws Exception
    {
        KEM kem = KEM.getInstance("SM9-KEM", "BC");
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)masterPair.getPrivate();

        // a master public key is not a recipient key
        try
        {
            kem.newEncapsulator(masterPair.getPublic(), null, null);
            fail("encapsulator accepted a non-recipient key");
        }
        catch (InvalidKeyException expected)
        {
        }

        // specs refused when the encapsulator is built, with the message where one is checked: a spec
        // other than a KTSParameterSpec; one with no key algorithm name, which SM9 checks itself as it
        // does not go through KdfUtil.resolveKemSpec; key sizes that are not a positive whole number of
        // bytes, as every other KEM refuses them (secretSize() is whole bytes, so they would silently
        // give fewer bits); and a KDF the provider cannot service, rather than failing in encapsulate()
        KTSParameterSpec nullName = new KTSParameterSpec.Builder(null, 256).withNoKdf().build();
        String badSize = "KTSParameterSpec key size must be a positive whole number of bytes: ";
        Object[][] badSpecs = {
            { new AlgorithmParameterSpec()
            {
            }, null, "a foreign spec" },
            { nullName, null, "a spec with no key algorithm name" },
            { new KTSParameterSpec.Builder("AES", 0).withNoKdf().build(), badSize + 0, "a key size of 0" },
            { new KTSParameterSpec.Builder("AES", 4).withNoKdf().build(), badSize + 4, "a key size of 4" },
            { new KTSParameterSpec.Builder("AES", 12).withNoKdf().build(), badSize + 12, "a key size of 12" },
            { new KTSParameterSpec.Builder("AES", 128).withKdfAlgorithm(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5"))).build(), "unsupported KDF: 1.2.3.4.5",
                "an unserviceable KDF" } };
        for (int i = 0; i != badSpecs.length; i++)
        {
            try
            {
                kem.newEncapsulator(bobPublic, (AlgorithmParameterSpec)badSpecs[i][0], null);
                fail("encapsulator accepted " + badSpecs[i][2]);
            }
            catch (InvalidAlgorithmParameterException expected)
            {
                if (badSpecs[i][1] != null)
                {
                    assertEquals((String)badSpecs[i][1], expected.getMessage());
                }
            }
        }
        try
        {
            kem.newDecapsulator(bob.getPrivate(), nullName);
            fail("decapsulator accepted a spec with no key algorithm name");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        // a key-exchange key is the wrong kind of key for decapsulation, and a recipient key formed
        // under HID_EXCHANGE for encapsulation, as no decapsulation key can be derived under that hid
        try
        {
            kem.newDecapsulator(masterPriv.generateExchangeKeyPair(bobIdentity).getPrivate(), null);
            fail("decapsulator accepted a key-exchange key");
        }
        catch (InvalidKeyException expected)
        {
            assertEquals("SM9 KEM decapsulation requires an encryption user key, not a key-exchange key",
                expected.getMessage());
        }
        try
        {
            kem.newEncapsulator(masterPriv.generateExchangeKeyPair(bobIdentity).getPublic(), null, null);
            fail("encapsulator accepted a recipient key under HID_EXCHANGE");
        }
        catch (InvalidKeyException expected)
        {
            assertEquals("SM9 KEM encapsulation requires an encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)",
                expected.getMessage());
        }
    }

    /**
     * The spec/algorithm reconciliation - "Generic" on either side deferring to the other, a genuine
     * mismatch refused - which testKEM's null spec cannot reach, both sides being "Generic" there.
     */
    public void testAlgorithmReconciliation()
        throws Exception
    {
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
