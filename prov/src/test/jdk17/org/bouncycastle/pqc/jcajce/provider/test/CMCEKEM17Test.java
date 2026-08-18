package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
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
 * services. Key generation is expensive here (a few hundred milliseconds per key pair), so the
 * operational cases share one key pair of the smallest code size, one representative of each of
 * the four sizes carries the round-trip sweep, and the all-16 registration sweep needs no keys.
 */
public class CMCEKEM17Test
    extends TestCase
{
    private static final CMCEParameterSpec[] SPECS = new CMCEParameterSpec[]{
        CMCEParameterSpec.mceliece460896, CMCEParameterSpec.mceliece460896f,
        CMCEParameterSpec.mceliece460896pc, CMCEParameterSpec.mceliece460896pcf,
        CMCEParameterSpec.mceliece6688128, CMCEParameterSpec.mceliece6688128f,
        CMCEParameterSpec.mceliece6688128pc, CMCEParameterSpec.mceliece6688128pcf,
        CMCEParameterSpec.mceliece6960119, CMCEParameterSpec.mceliece6960119f,
        CMCEParameterSpec.mceliece6960119pc, CMCEParameterSpec.mceliece6960119pcf,
        CMCEParameterSpec.mceliece8192128, CMCEParameterSpec.mceliece8192128f,
        CMCEParameterSpec.mceliece8192128pc, CMCEParameterSpec.mceliece8192128pcf
    };

    private static final ASN1ObjectIdentifier[] OIDS = new ASN1ObjectIdentifier[]{
        ISOIECObjectIdentifiers.mceliece460896, ISOIECObjectIdentifiers.mceliece460896f,
        ISOIECObjectIdentifiers.mceliece460896pc, ISOIECObjectIdentifiers.mceliece460896pcf,
        ISOIECObjectIdentifiers.mceliece6688128, ISOIECObjectIdentifiers.mceliece6688128f,
        ISOIECObjectIdentifiers.mceliece6688128pc, ISOIECObjectIdentifiers.mceliece6688128pcf,
        ISOIECObjectIdentifiers.mceliece6960119, ISOIECObjectIdentifiers.mceliece6960119f,
        ISOIECObjectIdentifiers.mceliece6960119pc, ISOIECObjectIdentifiers.mceliece6960119pcf,
        ISOIECObjectIdentifiers.mceliece8192128, ISOIECObjectIdentifiers.mceliece8192128f,
        ISOIECObjectIdentifiers.mceliece8192128pc, ISOIECObjectIdentifiers.mceliece8192128pcf
    };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private KeyPair baseKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public void testKEM()
        throws Exception
    {
        // Receiver side
        KeyPair kp = baseKeyPair();
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("CMCE", "BC");
        KTSParameterSpec ktsSpec = null;
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsSpec, null);

        // mceliece460896's session key is 256-bit, as all sixteen standardised sets' are
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
        KeyPair kp = baseKeyPair();

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
        KeyPair kp = baseKeyPair();

        performKEM("AES", kp, new KEMParameterSpec("AES"));
        performKEM("AES sliced", kp, 0, 16, "AES", new KEMParameterSpec("AES"));
        performKEM("AES-KWP", kp, new KEMParameterSpec("AES-KWP"));

        try
        {
            performKEM("mismatch", kp, 0, 16, "AES-KWP", new KEMParameterSpec("AES"));
            fail("spec/algorithm mismatch accepted");
        }
        catch (UnsupportedOperationException expected)
        {
            assertEquals("AES does not match AES-KWP", expected.getMessage());
        }
    }

    public void testBasicKEMOtherAlgorithms()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

        performKEM("Camellia", kp, new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEM("Camellia-KWP", kp, new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
        performKEM("SEED", kp, new KTSParameterSpec.Builder("SEED", 128).build());
        performKEM("ARIA", kp, new KEMParameterSpec("ARIA"));
        performKEM("ARIA-KWP", kp, new KEMParameterSpec("ARIA-KWP"));
    }

    /**
     * A KDF-less spec asking for more than the 256-bit session key is unsatisfiable. The KTS
     * wrapping path shortens the KEK to the secret it has, but javax.crypto.KEM validates
     * encapsulate()'s range against secretSize(), so the spec has to be refused up front.
     */
    public void testUnsatisfiableNoKdfSpecRefused()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

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
        performKEM("512 with KDF", kp, new KTSParameterSpec.Builder("AES", 512).build());
        performKEM("256 no-KDF", kp, new KTSParameterSpec.Builder("AES", 256).withNoKdf().build());
    }

    /**
     * KTSParameterSpec does not validate its own key size. A size below 8 would yield a
     * zero-length secret key (makeKeyBytes rounds the byte count up while secretSize() rounds it
     * down, so SecretKeySpec's own "Empty key" check never fires), one that is not a whole number
     * of bytes silently delivers fewer bits than were asked for, and one within 7 of
     * Integer.MAX_VALUE overflows the rounding-up itself.
     */
    public void testInvalidKeySizeRefused()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

        KEM kem = KEM.getInstance("CMCE", "BC");

        int[] sizes = new int[]{0, -8, -1, 1, 4, 7, 100, 252, Integer.MAX_VALUE};
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

        performKEM("8 boundary", kp, new KTSParameterSpec.Builder("AES", 8).withNoKdf().build());
    }

    /**
     * A KDF the spec is willing to carry but KdfUtil cannot service has to be refused with the
     * spec, not left to fail as an undeclared unchecked exception from encapsulate().
     */
    public void testUnsupportedKdfRefused()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

        AlgorithmIdentifier[] unsupported = new AlgorithmIdentifier[]{
            new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")),
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384)),
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3)
        };

        KEM kem = KEM.getInstance("CMCE", "BC");
        for (int i = 0; i != unsupported.length; i++)
        {
            KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256)
                .withKdfAlgorithm(unsupported[i]).build();

            try
            {
                kem.newEncapsulator(kp.getPublic(), spec, null);
                fail("encapsulator accepted unsupported KDF " + unsupported[i].getAlgorithm());
            }
            catch (InvalidAlgorithmParameterException expected)
            {
            }

            try
            {
                kem.newDecapsulator(kp.getPrivate(), spec);
                fail("decapsulator accepted unsupported KDF " + unsupported[i].getAlgorithm());
            }
            catch (InvalidAlgorithmParameterException expected)
            {
            }
        }

        performKEM("default KDF", kp, new KTSParameterSpec.Builder("AES", 256).build());
    }

    /**
     * A spec with no key algorithm name would be substituted for a "Generic" request and reach
     * SecretKeySpec as a null, past engineEncapsulate's own requireNonNull guard.
     */
    public void testNullKeyAlgorithmNameRefused()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

        KTSParameterSpec spec = new KTSParameterSpec.Builder(null, 256).withNoKdf().build();

        try
        {
            KEM.getInstance("CMCE", "BC").newEncapsulator(kp.getPublic(), spec, null);
            fail("encapsulator accepted a spec with no key algorithm name");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        try
        {
            KEM.getInstance("CMCE", "BC").newDecapsulator(kp.getPrivate(), spec);
            fail("decapsulator accepted a spec with no key algorithm name");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }
    }

    /**
     * The decapsulator carries its own copy of the spec/algorithm reconciliation, and the
     * encapsulate-then-decapsulate helpers can never reach it - a mismatch always fails on the
     * encapsulate leg first. Drive the decapsulate leg directly.
     */
    public void testDecapsulatorAlgorithmMismatch()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

        KTSParameterSpec aes = new KEMParameterSpec("AES");
        KEM.Encapsulated enc = KEM.getInstance("CMCE", "BC")
            .newEncapsulator(kp.getPublic(), aes, null).encapsulate(0, 16, "AES");

        KEM.Decapsulator d = KEM.getInstance("CMCE", "BC").newDecapsulator(kp.getPrivate(), aes);

        try
        {
            d.decapsulate(enc.encapsulation(), 0, 16, "AES-KWP");
            fail("decapsulator accepted an algorithm its spec does not name");
        }
        catch (UnsupportedOperationException expected)
        {
            assertEquals("AES does not match AES-KWP", expected.getMessage());
        }

        assertTrue(Arrays.areEqual(enc.key().getEncoded(),
            d.decapsulate(enc.encapsulation(), 0, 16, "AES").getEncoded()));
    }

    /**
     * Every one of the sixteen parameter-set locked services is registered, is distinct from the
     * unrestricted one and from its siblings, and its ISO/IEC 18033-2 object identifier resolves
     * to the same class - the invariant a 16-way copy-paste block can break silently. Costs no
     * key generation, which is why it can afford to cover all sixteen.
     */
    public void testAllLockedServicesRegistered()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        String unrestricted = bc.getService("KEM", "CMCE").getClassName();
        Set<String> seen = new HashSet<String>();

        for (int i = 0; i != SPECS.length; i++)
        {
            String name = SPECS[i].getName();

            Provider.Service byName = bc.getService("KEM", name);
            assertNotNull("no KEM service for " + name, byName);
            assertFalse(name + " resolved to the unrestricted service",
                unrestricted.equals(byName.getClassName()));
            assertTrue(name + " shares a class with an earlier set: " + byName.getClassName(),
                seen.add(byName.getClassName()));

            Provider.Service byOid = bc.getService("KEM", OIDS[i].getId());
            assertNotNull("no KEM service for OID " + OIDS[i].getId(), byOid);
            assertEquals(name + " OID resolves elsewhere",
                byName.getClassName(), byOid.getClassName());
        }
    }

    /**
     * The parameter-set locked services accept a key of their own set only.
     */
    public void testParameterSetLockedServices()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
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

        // the OID alias is the same locked service, so it refuses the other set's key too
        KEM byOid = KEM.getInstance(ISOIECObjectIdentifiers.mceliece460896.getId(), "BC");
        assertTrue(Arrays.areEqual(enc.key().getEncoded(),
            byOid.newDecapsulator(kp.getPrivate(), null).decapsulate(enc.encapsulation()).getEncoded()));
        try
        {
            byOid.newDecapsulator(other.getPrivate(), null);
            fail("OID-resolved decapsulator accepted a key of another parameter set");
        }
        catch (InvalidKeyException expected)
        {
        }
    }

    public void testGuards()
        throws Exception
    {
        KeyPair kp = baseKeyPair();

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

        KEM.Encapsulator e = kem.newEncapsulator(kp.getPublic(), null, null);
        KEM.Encapsulated enc = e.encapsulate();
        KEM.Decapsulator d = kem.newDecapsulator(kp.getPrivate(), null);

        // javax.crypto.KEM delegates without validating, so the SPI's own range and null guards
        // are the only ones there are
        try
        {
            e.encapsulate(0, e.secretSize() + 1, "AES");
            fail("encapsulate accepted a range past secretSize()");
        }
        catch (IndexOutOfBoundsException expected)
        {
        }

        try
        {
            d.decapsulate(enc.encapsulation(), 0, d.secretSize() + 1, "AES");
            fail("decapsulate accepted a range past secretSize()");
        }
        catch (IndexOutOfBoundsException expected)
        {
        }

        try
        {
            d.decapsulate(null);
            fail("decapsulate accepted a null encapsulation");
        }
        catch (NullPointerException expected)
        {
        }

        // a short encapsulation is rejected rather than decoded
        try
        {
            d.decapsulate(Arrays.copyOfRange(enc.encapsulation(), 0, enc.encapsulation().length - 1));
            fail("decapsulator accepted a truncated encapsulation");
        }
        catch (DecapsulateException expected)
        {
        }
    }

    /**
     * javax.crypto.KEM requires a Decapsulator to be safe for concurrent use.
     */
    public void testConcurrentDecapsulation()
        throws Exception
    {
        final KeyPair kp = baseKeyPair();

        final int count = 16;
        final byte[][] encapsulations = new byte[count][];
        final byte[][] expected = new byte[count][];

        KEM.Encapsulator e = KEM.getInstance("CMCE", "BC").newEncapsulator(kp.getPublic(), null, null);
        for (int i = 0; i != count; i++)
        {
            KEM.Encapsulated enc = e.encapsulate();
            encapsulations[i] = enc.encapsulation();
            expected[i] = enc.key().getEncoded();
        }

        final KEM.Decapsulator d = KEM.getInstance("CMCE", "BC").newDecapsulator(kp.getPrivate(), null);
        final Throwable[] failure = new Throwable[1];
        final int[] mismatches = new int[1];

        Thread[] threads = new Thread[4];
        for (int t = 0; t != threads.length; t++)
        {
            threads[t] = new Thread()
            {
                public void run()
                {
                    for (int i = 0; i != count; i++)
                    {
                        try
                        {
                            byte[] got = d.decapsulate(encapsulations[i]).getEncoded();
                            if (!Arrays.areEqual(got, expected[i]))
                            {
                                synchronized (mismatches)
                                {
                                    mismatches[0]++;
                                }
                            }
                        }
                        catch (Throwable th)
                        {
                            failure[0] = th;
                        }
                    }
                }
            };
            threads[t].start();
        }
        for (int t = 0; t != threads.length; t++)
        {
            threads[t].join();
        }

        assertNull("concurrent decapsulation threw " + failure[0], failure[0]);
        assertEquals("concurrent decapsulation produced wrong secrets", 0, mismatches[0]);
    }

    private void performKEM(String label, KeyPair kp, int from, int to, String algorithm,
        KTSParameterSpec ktsParameterSpec)
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
        assertEquals(label, secS.getAlgorithm(), secR.getAlgorithm());
        assertEquals(label, to - from, secS.getEncoded().length);
        assertTrue(label, Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    private void performKEM(String label, KeyPair kp, KTSParameterSpec ktsParameterSpec)
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
        assertEquals(label, secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(label, Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }
}
