package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 * javax.crypto.KEM API tests for the standardised FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026,
 * Clause 14) - {@code KEM.FRODOKEM} and the parameter-set locked services.
 */
public class FrodoKEM17Test
    extends TestCase
{
    private static final FrodoKEMParameterSpec[] SPECS = new FrodoKEMParameterSpec[]{
        FrodoKEMParameterSpec.frodokem976shake,
        FrodoKEMParameterSpec.frodokem1344shake,
        FrodoKEMParameterSpec.efrodokem976shake,
        FrodoKEMParameterSpec.efrodokem1344shake,
        FrodoKEMParameterSpec.frodokem976aes,
        FrodoKEMParameterSpec.frodokem1344aes,
        FrodoKEMParameterSpec.efrodokem976aes,
        FrodoKEMParameterSpec.efrodokem1344aes
    };

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
        KeyPairGenerator g = KeyPairGenerator.getInstance("FRODOKEM", "BC");

        g.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());

        KeyPair kp = g.generateKeyPair();
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("FRODOKEM", "BC");
        KTSParameterSpec ktsSpec = null;
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        assertEquals(em.length, e.encapsulationSize());

        // Receiver side
        KEM kemR = KEM.getInstance("FRODOKEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsSpec);
        SecretKey secR = d.decapsulate(em);

        assertEquals(e.secretSize(), d.secretSize());
        assertEquals(e.encapsulationSize(), d.encapsulationSize());

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    /**
     * Unlike ML-KEM, FrodoKEM's session key size varies with the parameter set - 24 bytes for the
     * 976 sets, 32 for the 1344 sets - so the default (no KDF) secret size has to come from the
     * key rather than being a fixed 256 bits. Every standardised set is exercised.
     */
    public void testDefaultSecretSizeFollowsParameterSet()
        throws Exception
    {
        for (int i = 0; i != SPECS.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
            kpg.initialize(SPECS[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            int expected = SPECS[i].getName().contains("1344") ? 32 : 24;

            KEM.Encapsulator e = KEM.getInstance("FRODOKEM", "BC").newEncapsulator(kp.getPublic(), null, null);
            assertEquals(SPECS[i].getName(), expected, e.secretSize());

            KEM.Encapsulated enc = e.encapsulate();
            assertEquals(SPECS[i].getName(), expected, enc.key().getEncoded().length);

            KEM.Decapsulator d = KEM.getInstance("FRODOKEM", "BC").newDecapsulator(kp.getPrivate(), null);
            assertEquals(SPECS[i].getName(), expected, d.secretSize());
            assertTrue(SPECS[i].getName(), Arrays.areEqual(enc.key().getEncoded(), d.decapsulate(enc.encapsulation()).getEncoded()));
        }
    }

    /**
     * With no KDF the KEM API secret is the mechanism's own session key, so the pre-existing
     * KeyGenerator bridge recovers an identical key from the same encapsulation.
     */
    public void testNoKdfMatchesKeyGeneratorBridge()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem1344shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KTSParameterSpec noKdf = new KTSParameterSpec.Builder("AES", 256).withNoKdf().build();
        KEM.Encapsulator e = KEM.getInstance("FRODOKEM", "BC").newEncapsulator(kp.getPublic(), noKdf, null);
        KEM.Encapsulated enc = e.encapsulate();

        assertEquals("AES", enc.key().getAlgorithm());
        assertEquals(32, enc.key().getEncoded().length);

        KeyGenerator decapsulator = KeyGenerator.getInstance("FRODOKEM", "BC");
        decapsulator.init(new KEMExtractSpec.Builder(kp.getPrivate(), enc.encapsulation(), "AES", 256)
            .withNoKdf().build());
        SecretKeyWithEncapsulation viaKeyGenerator = (SecretKeyWithEncapsulation)decapsulator.generateKey();

        assertTrue(Arrays.areEqual(enc.key().getEncoded(), viaKeyGenerator.getEncoded()));
    }

    public void testBasicKEMAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());

        // KTSParameterSpec carries the default KDF (X9.44 KDF-3 / SHA-256), so a 256-bit key is
        // derivable from frodokem976shake's 192-bit session key
        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("AES", 256).build());
        performKEM(kpg.generateKeyPair(), 0, 16, "AES", new KTSParameterSpec.Builder("AES", 256).build());
        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("AES-KWP", 256).build());

        try
        {
            performKEM(kpg.generateKeyPair(), 0, 16, "AES-KWP", new KTSParameterSpec.Builder("AES", 256).build());
            fail("spec/algorithm mismatch accepted");
        }
        catch (UnsupportedOperationException expected)
        {
        }

        // the 1344 sets give a 256-bit session key, so no KDF is needed for a 256-bit AES key
        kpg.initialize(FrodoKEMParameterSpec.efrodokem1344aes, new SecureRandom());
        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("AES", 256).withNoKdf().build());
    }

    public void testBasicKEMOtherAlgorithms()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("SEED", 128).build());
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("ARIA", 128));
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("ARIA-KWP", 128));
    }

    /**
     * A KDF-less spec asking for more than the parameter set's own session key is unsatisfiable.
     * The KTS wrapping path shortens the KEK to the secret it has, but javax.crypto.KEM validates
     * encapsulate()'s range against secretSize(), so the spec has to be refused up front - and the
     * deprecated KEMParameterSpec, which is KDF-less and 256-bit by default, is the way a caller
     * runs into it on a 976 set.
     */
    public void testUnsatisfiableNoKdfSpecRefused()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("FRODOKEM", "BC");

        try
        {
            kem.newEncapsulator(kp.getPublic(), new KEMParameterSpec("AES"), null);
            fail("encapsulator accepted a 256 bit KDF-less spec on a 192 bit secret");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            assertTrue(expected.getMessage().contains("frodokem976shake"));
        }

        try
        {
            kem.newDecapsulator(kp.getPrivate(), new KTSParameterSpec.Builder("AES", 256).withNoKdf().build());
            fail("decapsulator accepted a 256 bit KDF-less spec on a 192 bit secret");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        // the same request with a KDF, or sized to the session key, is fine
        performKEM(kp, new KEMParameterSpec("AES", 192));
        performKEM(kp, new KTSParameterSpec.Builder("AES", 256).build());
    }

    /**
     * KTSParameterSpec does not validate its own key size, so a non-positive one has to be rejected
     * here - otherwise it surfaces as an undeclared unchecked exception (an "Empty key"
     * IllegalArgumentException at 0, an IndexOutOfBoundsException when negative) out of
     * encapsulate() / decapsulate() instead of as a spec failure where the caller can act on it.
     */
    public void testNonPositiveKeySizeRefused()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("FRODOKEM", "BC");

        int[] sizes = new int[]{0, -8};
        for (int i = 0; i != sizes.length; i++)
        {
            KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", sizes[i]).withNoKdf().build();

            try
            {
                kem.newEncapsulator(kp.getPublic(), spec, null);
                fail("encapsulator accepted key size " + sizes[i]);
            }
            catch (InvalidAlgorithmParameterException expected)
            {
            }

            try
            {
                kem.newDecapsulator(kp.getPrivate(), spec);
                fail("decapsulator accepted key size " + sizes[i]);
            }
            catch (InvalidAlgorithmParameterException expected)
            {
            }
        }
    }

    /**
     * The parameter-set locked services accept a key of their own set only, and the ISO/IEC
     * 18033-2 object identifier resolves as a KEM name - what a caller dispatching on the OID in a
     * received encoding does.
     */
    public void testParameterSetLockedServices()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        kpg.initialize(FrodoKEMParameterSpec.efrodokem976shake, new SecureRandom());
        KeyPair other = kpg.generateKeyPair();

        KEM locked = KEM.getInstance("frodokem976shake", "BC");
        KEM.Encapsulated enc = locked.newEncapsulator(kp.getPublic(), null, null).encapsulate();
        assertTrue(Arrays.areEqual(enc.key().getEncoded(),
            locked.newDecapsulator(kp.getPrivate(), null).decapsulate(enc.encapsulation()).getEncoded()));

        try
        {
            locked.newEncapsulator(other.getPublic(), null, null);
            fail("locked encapsulator accepted a key of another parameter set");
        }
        catch (InvalidKeyException expected)
        {
        }

        try
        {
            locked.newDecapsulator(other.getPrivate(), null);
            fail("locked decapsulator accepted a key of another parameter set");
        }
        catch (InvalidKeyException expected)
        {
        }

        // the OID alias resolves to the same locked service
        KEM byOid = KEM.getInstance(ISOIECObjectIdentifiers.frodokem976_shake.getId(), "BC");
        assertTrue(Arrays.areEqual(enc.key().getEncoded(),
            byOid.newDecapsulator(kp.getPrivate(), null).decapsulate(enc.encapsulation()).getEncoded()));
    }

    public void testGuards()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("FRODOKEM", "BC");

        // a foreign key type is not a FrodoKEM key
        KeyPair rsa = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        try
        {
            kem.newEncapsulator(rsa.getPublic(), null, null);
            fail("encapsulator accepted a foreign key");
        }
        catch (InvalidKeyException expected)
        {
        }

        try
        {
            kem.newDecapsulator(rsa.getPrivate(), null);
            fail("decapsulator accepted a foreign key");
        }
        catch (InvalidKeyException expected)
        {
        }

        // only KTSParameterSpec is understood
        try
        {
            kem.newEncapsulator(kp.getPublic(), new AlgorithmParameterSpec()
            {
            }, null);
            fail("encapsulator accepted a foreign spec");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        // a short encapsulation is rejected rather than decoded
        KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic(), null, null).encapsulate();
        KEM.Decapsulator d = kem.newDecapsulator(kp.getPrivate(), null);
        try
        {
            d.decapsulate(Arrays.copyOfRange(enc.encapsulation(), 0, enc.encapsulation().length - 1));
            fail("decapsulator accepted a truncated encapsulation");
        }
        catch (DecapsulateException expected)
        {
        }
    }

    private void performKEM(KeyPair kp, int from, int to, String algorithm, KTSParameterSpec ktsParameterSpec)
        throws Exception
    {
        // Sender side
        KEM kemS = KEM.getInstance("FRODOKEM", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate(from, to, algorithm);
        SecretKey secS = enc.key();

        // Receiver side
        KEM kemR = KEM.getInstance("FRODOKEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(enc.encapsulation(), from, to, algorithm);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertEquals(to - from, secS.getEncoded().length);
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    private void performKEM(KeyPair kp, KTSParameterSpec ktsParameterSpec)
        throws Exception
    {
        // Sender side
        KEM kemS = KEM.getInstance("FRODOKEM", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();

        // Receiver side
        KEM kemR = KEM.getInstance("FRODOKEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(enc.encapsulation());

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }
}
