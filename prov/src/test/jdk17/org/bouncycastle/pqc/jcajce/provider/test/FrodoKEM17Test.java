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

    private static final ASN1ObjectIdentifier[] OIDS = new ASN1ObjectIdentifier[]{
        ISOIECObjectIdentifiers.frodokem976_shake,
        ISOIECObjectIdentifiers.frodokem1344_shake,
        ISOIECObjectIdentifiers.efrodokem976_shake,
        ISOIECObjectIdentifiers.efrodokem1344_shake,
        ISOIECObjectIdentifiers.frodokem976_aes,
        ISOIECObjectIdentifiers.frodokem1344_aes,
        ISOIECObjectIdentifiers.efrodokem976_aes,
        ISOIECObjectIdentifiers.efrodokem1344_aes
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
        KeyPair kp = kpg.generateKeyPair();

        // KTSParameterSpec carries the default KDF (X9.44 KDF-3 / SHA-256), so a 256-bit key is
        // derivable from frodokem976shake's 192-bit session key
        performKEM("AES", kp, new KTSParameterSpec.Builder("AES", 256).build());
        performKEM("AES sliced", kp, 0, 16, "AES", new KTSParameterSpec.Builder("AES", 256).build());
        performKEM("AES-KWP", kp, new KTSParameterSpec.Builder("AES-KWP", 256).build());

        try
        {
            performKEM("mismatch", kp, 0, 16, "AES-KWP", new KTSParameterSpec.Builder("AES", 256).build());
            fail("spec/algorithm mismatch accepted");
        }
        catch (UnsupportedOperationException expected)
        {
            assertEquals("AES does not match AES-KWP", expected.getMessage());
        }

        // the 1344 sets give a 256-bit session key, so no KDF is needed for a 256-bit AES key
        kpg.initialize(FrodoKEMParameterSpec.efrodokem1344aes, new SecureRandom());
        performKEM("1344 no-KDF", kpg.generateKeyPair(),
            new KTSParameterSpec.Builder("AES", 256).withNoKdf().build());
    }

    public void testBasicKEMOtherAlgorithms()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        performKEM("Camellia", kp, new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEM("Camellia-KWP", kp, new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
        performKEM("SEED", kp, new KTSParameterSpec.Builder("SEED", 128).build());
        performKEM("ARIA", kp, new KEMParameterSpec("ARIA", 128));
        performKEM("ARIA-KWP", kp, new KEMParameterSpec("ARIA-KWP", 128));
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
        performKEM("192 no-KDF", kp, new KEMParameterSpec("AES", 192));
        performKEM("256 with KDF", kp, new KTSParameterSpec.Builder("AES", 256).build());
    }

    /**
     * KTSParameterSpec does not validate its own key size. A size below 8 would yield a
     * zero-length secret key (makeKeyBytes rounds the byte count up while secretSize() rounds it
     * down, so SecretKeySpec's own "Empty key" check never fires), one that is not a whole number
     * of bytes silently delivers fewer bits than were asked for, and one within 7 of
     * Integer.MAX_VALUE overflows the rounding-up itself - so all of them are refused as spec
     * failures rather than surfacing later out of encapsulate() / decapsulate().
     */
    public void testInvalidKeySizeRefused()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KEM kem = KEM.getInstance("FRODOKEM", "BC");

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

        // a whole number of bytes within the session key is still accepted
        performKEM("192 boundary", kp, new KTSParameterSpec.Builder("AES", 192).withNoKdf().build());
        performKEM("8 boundary", kp, new KTSParameterSpec.Builder("AES", 8).withNoKdf().build());
    }

    /**
     * A KDF the spec is willing to carry but KdfUtil cannot service has to be refused with the
     * spec, not left to fail as an undeclared unchecked exception from encapsulate().
     */
    public void testUnsupportedKdfRefused()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        AlgorithmIdentifier[] unsupported = new AlgorithmIdentifier[]{
            // an OID that names no KDF at all
            new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")),
            // KDF2/KDF3 naming a digest getDigest() does not know
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384)),
            // KDF3 with its mandatory digest parameters absent
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3)
        };

        KEM kem = KEM.getInstance("FRODOKEM", "BC");
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

        // the default KDF3/SHA-256 the builder installs is of course serviceable
        performKEM("default KDF", kp, new KTSParameterSpec.Builder("AES", 256).build());
    }

    /**
     * A spec with no key algorithm name would be substituted for a "Generic" request and reach
     * SecretKeySpec as a null, past engineEncapsulate's own requireNonNull guard.
     */
    public void testNullKeyAlgorithmNameRefused()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KTSParameterSpec spec = new KTSParameterSpec.Builder(null, 192).withNoKdf().build();

        try
        {
            KEM.getInstance("FRODOKEM", "BC").newEncapsulator(kp.getPublic(), spec, null);
            fail("encapsulator accepted a spec with no key algorithm name");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        try
        {
            KEM.getInstance("FRODOKEM", "BC").newDecapsulator(kp.getPrivate(), spec);
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KTSParameterSpec aes = new KTSParameterSpec.Builder("AES", 256).build();
        KEM.Encapsulated enc = KEM.getInstance("FRODOKEM", "BC")
            .newEncapsulator(kp.getPublic(), aes, null).encapsulate(0, 16, "AES");

        KEM.Decapsulator d = KEM.getInstance("FRODOKEM", "BC").newDecapsulator(kp.getPrivate(), aes);

        try
        {
            d.decapsulate(enc.encapsulation(), 0, 16, "AES-KWP");
            fail("decapsulator accepted an algorithm its spec does not name");
        }
        catch (UnsupportedOperationException expected)
        {
            assertEquals("AES does not match AES-KWP", expected.getMessage());
        }

        // the matching algorithm still works
        assertTrue(Arrays.areEqual(enc.key().getEncoded(),
            d.decapsulate(enc.encapsulation(), 0, 16, "AES").getEncoded()));
    }

    /**
     * Every parameter-set locked service is registered, is distinct from the unrestricted one and
     * from its siblings, and its ISO/IEC 18033-2 object identifier resolves to the same class -
     * the invariant a 8-way copy-paste block can break silently. No key generation needed.
     */
    public void testAllLockedServicesRegistered()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        String unrestricted = bc.getService("KEM", "FRODOKEM").getClassName();
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

        // the OID alias is the same locked service, so it refuses the other set's key too
        KEM byOid = KEM.getInstance(ISOIECObjectIdentifiers.frodokem976_shake.getId(), "BC");
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
     * javax.crypto.KEM requires a Decapsulator to be safe for concurrent use. A FrodoKEMExtractor
     * holds one FrodoKEMEngine whose SHAKE digest is mutable, so sharing one across calls returned
     * wrong secrets and threw "attempt to absorb while squeezing"; the SPI builds one per call.
     */
    public void testConcurrentDecapsulation()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());
        final KeyPair kp = kpg.generateKeyPair();

        final int count = 24;
        final byte[][] encapsulations = new byte[count][];
        final byte[][] expected = new byte[count][];

        KEM.Encapsulator e = KEM.getInstance("FRODOKEM", "BC").newEncapsulator(kp.getPublic(), null, null);
        for (int i = 0; i != count; i++)
        {
            KEM.Encapsulated enc = e.encapsulate();
            encapsulations[i] = enc.encapsulation();
            expected[i] = enc.key().getEncoded();
        }

        // one Decapsulator, shared - the usage javax.crypto.KEM documents as safe
        final KEM.Decapsulator d = KEM.getInstance("FRODOKEM", "BC").newDecapsulator(kp.getPrivate(), null);
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
        KEM kemS = KEM.getInstance("FRODOKEM", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate(from, to, algorithm);
        SecretKey secS = enc.key();

        // Receiver side
        KEM kemR = KEM.getInstance("FRODOKEM", "BC");
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
        KEM kemS = KEM.getInstance("FRODOKEM", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();

        // Receiver side
        KEM kemR = KEM.getInstance("FRODOKEM", "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(enc.encapsulation());

        // secS and secR will be identical
        assertEquals(label, secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(label, Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }
}
