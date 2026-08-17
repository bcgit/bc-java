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
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 * javax.crypto.KEM API tests for the standardised Classic McEliece KEM
 * (ISO/IEC 18033-2:2006/Amd 2:2026, Clause 13) - {@code KEM.CMCE} and the parameter-set locked
 * services. Key generation is expensive here, so the operational cases use the smallest code size
 * and one representative of each of the four sizes carries the round-trip sweep.
 */
public class CMCEKEM17Test
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
        KeyPairGenerator g = KeyPairGenerator.getInstance("CMCE", "BC");

        g.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());

        KeyPair kp = g.generateKeyPair();
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("CMCE", "BC");
        KTSParameterSpec ktsSpec = null;
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsSpec, null);

        // all sixteen standardised sets produce a 256-bit session key
        assertEquals(32, e.secretSize());

        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        assertEquals(em.length, e.encapsulationSize());

        // Receiver side
        KEM kemR = KEM.getInstance("CMCE", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsSpec);
        SecretKey secR = d.decapsulate(em);

        assertEquals(e.secretSize(), d.secretSize());
        assertEquals(e.encapsulationSize(), d.encapsulationSize());

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    /**
     * One representative of each standardised code size, covering both the plaintext-confirmation
     * ("pc") and semi-systematic ("f") variants - the encapsulation size is the only thing that
     * varies across them, the session key is 256-bit throughout.
     */
    public void testRoundTripAcrossCodeSizes()
        throws Exception
    {
        CMCEParameterSpec[] specs = new CMCEParameterSpec[]{
            CMCEParameterSpec.mceliece460896,
            CMCEParameterSpec.mceliece6688128f,
            CMCEParameterSpec.mceliece6960119pc,
            CMCEParameterSpec.mceliece8192128pcf
        };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
            kpg.initialize(specs[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            KEM.Encapsulator e = KEM.getInstance("CMCE", "BC").newEncapsulator(kp.getPublic(), null, null);
            assertEquals(specs[i].getName(), 32, e.secretSize());

            KEM.Encapsulated enc = e.encapsulate();
            assertEquals(specs[i].getName(), 32, enc.key().getEncoded().length);
            assertEquals(specs[i].getName(), e.encapsulationSize(), enc.encapsulation().length);

            KEM.Decapsulator d = KEM.getInstance("CMCE", "BC").newDecapsulator(kp.getPrivate(), null);
            assertEquals(specs[i].getName(), e.encapsulationSize(), d.encapsulationSize());
            assertTrue(specs[i].getName(), Arrays.areEqual(enc.key().getEncoded(),
                d.decapsulate(enc.encapsulation()).getEncoded()));
        }
    }

    /**
     * With no KDF the KEM API secret is the mechanism's own session key, so the pre-existing
     * KeyGenerator bridge recovers an identical key from the same encapsulation.
     */
    public void testNoKdfMatchesKeyGeneratorBridge()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KTSParameterSpec noKdf = new KTSParameterSpec.Builder("AES", 256).withNoKdf().build();
        KEM.Encapsulator e = KEM.getInstance("CMCE", "BC").newEncapsulator(kp.getPublic(), noKdf, null);
        KEM.Encapsulated enc = e.encapsulate();

        assertEquals("AES", enc.key().getAlgorithm());
        assertEquals(32, enc.key().getEncoded().length);

        KeyGenerator decapsulator = KeyGenerator.getInstance("CMCE", "BC");
        decapsulator.init(new KEMExtractSpec.Builder(kp.getPrivate(), enc.encapsulation(), "AES", 256)
            .withNoKdf().build());
        SecretKeyWithEncapsulation viaKeyGenerator = (SecretKeyWithEncapsulation)decapsulator.generateKey();

        assertTrue(Arrays.areEqual(enc.key().getEncoded(), viaKeyGenerator.getEncoded()));
    }

    public void testBasicKEMAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        performKEM(kp, new KEMParameterSpec("AES"));
        performKEM(kp, 0, 16, "AES", new KEMParameterSpec("AES"));
        performKEM(kp, new KEMParameterSpec("AES-KWP"));

        try
        {
            performKEM(kp, 0, 16, "AES-KWP", new KEMParameterSpec("AES"));
            fail("spec/algorithm mismatch accepted");
        }
        catch (UnsupportedOperationException expected)
        {
        }
    }

    /**
     * A KDF-less spec asking for more than the 256-bit session key is unsatisfiable. The KTS
     * wrapping path shortens the KEK to the secret it has, but javax.crypto.KEM validates
     * encapsulate()'s range against secretSize(), so the spec has to be refused up front.
     */
    public void testUnsatisfiableNoKdfSpecRefused()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("CMCE", "BC");
        KTSParameterSpec tooBig = new KTSParameterSpec.Builder("AES", 512).withNoKdf().build();

        try
        {
            kem.newEncapsulator(kp.getPublic(), tooBig, null);
            fail("encapsulator accepted a 512 bit KDF-less spec on a 256 bit secret");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            assertTrue(expected.getMessage().contains("mceliece460896"));
        }

        try
        {
            kem.newDecapsulator(kp.getPrivate(), tooBig);
            fail("decapsulator accepted a 512 bit KDF-less spec on a 256 bit secret");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        // the same request with a KDF is fine - and 256 bits needs no KDF at all
        performKEM(kp, new KTSParameterSpec.Builder("AES", 512).build());
        performKEM(kp, new KTSParameterSpec.Builder("AES", 256).withNoKdf().build());
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("CMCE", "BC");

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

    public void testBasicKEMOtherAlgorithms()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        performKEM(kp, new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEM(kp, new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
        performKEM(kp, new KTSParameterSpec.Builder("SEED", 128).build());
        performKEM(kp, new KEMParameterSpec("ARIA"));
        performKEM(kp, new KEMParameterSpec("ARIA-KWP"));
    }

    /**
     * The parameter-set locked services accept a key of their own set only, and the ISO/IEC
     * 18033-2 object identifier resolves as a KEM name - what a caller dispatching on the OID in a
     * received encoding does.
     */
    public void testParameterSetLockedServices()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        kpg.initialize(CMCEParameterSpec.mceliece460896pc, new SecureRandom());
        KeyPair other = kpg.generateKeyPair();

        KEM locked = KEM.getInstance("mceliece460896", "BC");
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
        KEM byOid = KEM.getInstance(ISOIECObjectIdentifiers.mceliece460896.getId(), "BC");
        assertTrue(Arrays.areEqual(enc.key().getEncoded(),
            byOid.newDecapsulator(kp.getPrivate(), null).decapsulate(enc.encapsulation()).getEncoded()));
    }

    public void testGuards()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("CMCE", "BC");

        // a foreign key type is not a CMCE key
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
        KEM kemS = KEM.getInstance("CMCE", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate(from, to, algorithm);
        SecretKey secS = enc.key();

        // Receiver side
        KEM kemR = KEM.getInstance("CMCE", "BC");
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
        KEM kemS = KEM.getInstance("CMCE", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();

        // Receiver side
        KEM kemR = KEM.getInstance("CMCE", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(enc.encapsulation());

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }
}
