package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * javax.crypto.KEM API tests for NTRU+ - {@code KEM.NTRUPLUS} plus one parameter-set locked service per set. The family had
 * Cipher, KeyGenerator and KeyPairGenerator services but no KEM one until now.
 */
public class NTRUPlusKEM17Test
    extends TestCase
{
    private static final String KEM_NAME = "NTRUPLUS";
    private static final String KPG_NAME = "NTRUPLUS";

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    private KeyPair keyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KPG_NAME, "BCPQC");
        kpg.initialize(NTRUPlusParameterSpec.ntruplus_768, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public void testKEM()
        throws Exception
    {
        KeyPair kp = keyPair();

        KEM kemS = KEM.getInstance(KEM_NAME, "BCPQC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), null, null);
        assertEquals(32, e.secretSize());

        KEM.Encapsulated enc = e.encapsulate();
        assertEquals(enc.encapsulation().length, e.encapsulationSize());

        KEM.Decapsulator d = KEM.getInstance(KEM_NAME, "BCPQC").newDecapsulator(kp.getPrivate(), null);
        SecretKey secR = d.decapsulate(enc.encapsulation());

        // the two sides must agree on both sizes, or a valid encapsulation gets rejected
        assertEquals(e.secretSize(), d.secretSize());
        assertEquals(e.encapsulationSize(), d.encapsulationSize());

        assertEquals(enc.key().getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));
    }

    /**
     * Every parameter set round trips, and the encapsulator and decapsulator agree on the
     * encapsulation size - they derive it by different routes, so a mismatch would make the
     * decapsulator reject encapsulations its own peer produced.
     */
    public void testAllParameterSetsRoundTrip()
        throws Exception
    {
        for (int i = 0; i != SPECS.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KPG_NAME, "BCPQC");
            kpg.initialize(SPECS[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            String label = SPECS[i].getName();

            KEM.Encapsulator e = KEM.getInstance(KEM_NAME, "BCPQC").newEncapsulator(kp.getPublic(), null, null);
            KEM.Encapsulated enc = e.encapsulate();
            KEM.Decapsulator d = KEM.getInstance(KEM_NAME, "BCPQC").newDecapsulator(kp.getPrivate(), null);

            assertEquals(label, e.encapsulationSize(), d.encapsulationSize());
            assertEquals(label, e.encapsulationSize(), enc.encapsulation().length);
            assertEquals(label, 32, enc.key().getEncoded().length);
            assertTrue(label, Arrays.areEqual(enc.key().getEncoded(),
                d.decapsulate(enc.encapsulation()).getEncoded()));
        }
    }

    public void testWrapAlgorithms()
        throws Exception
    {
        KeyPair kp = keyPair();

        performKEM("AES", kp, new KTSParameterSpec.Builder("AES", 256).build());
        performKEM("AES no-KDF", kp, new KTSParameterSpec.Builder("AES", 256).withNoKdf().build());
        performKEM("AES-KWP", kp, new KTSParameterSpec.Builder("AES-KWP", 256).build());
        performKEM("Camellia", kp, new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEM("SEED", kp, new KTSParameterSpec.Builder("SEED", 128).build());
    }

    /**
     * Everything a KTSParameterSpec can carry that the KEM cannot honour has to be refused with the
     * spec, not left to fail as an undeclared unchecked exception out of encapsulate().
     */
    public void testSpecValidation()
        throws Exception
    {
        KeyPair kp = keyPair();
        KEM kem = KEM.getInstance(KEM_NAME, "BCPQC");

        // not a whole positive number of bytes, or over the session key with no KDF
        int[] sizes = new int[]{0, -8, 1, 7, 100, 252, Integer.MAX_VALUE, 512};
        for (int i = 0; i != sizes.length; i++)
        {
            KTSParameterSpec bad = new KTSParameterSpec.Builder("AES", sizes[i]).withNoKdf().build();
            try
            {
                kem.newEncapsulator(kp.getPublic(), bad, null);
                fail("encapsulator accepted key size " + sizes[i]);
            }
            catch (InvalidAlgorithmParameterException expected)
            {
            }
            try
            {
                kem.newDecapsulator(kp.getPrivate(), bad);
                fail("decapsulator accepted key size " + sizes[i]);
            }
            catch (InvalidAlgorithmParameterException expected)
            {
            }
        }

        // a KDF the provider cannot service
        KTSParameterSpec badKdf = new KTSParameterSpec.Builder("AES", 256)
            .withKdfAlgorithm(new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384))).build();
        try
        {
            kem.newEncapsulator(kp.getPublic(), badKdf, null);
            fail("encapsulator accepted an unsupported KDF");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        // a spec with no key algorithm name
        try
        {
            kem.newEncapsulator(kp.getPublic(), new KTSParameterSpec.Builder(null, 256).withNoKdf().build(), null);
            fail("encapsulator accepted a spec with no key algorithm name");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
        }

        // a foreign spec type
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
    }

    /**
     * The decapsulator carries its own copy of the spec/algorithm reconciliation, and an
     * encapsulate-then-decapsulate helper can never reach it - a mismatch fails on encapsulate first.
     */
    public void testDecapsulatorAlgorithmMismatch()
        throws Exception
    {
        KeyPair kp = keyPair();

        KTSParameterSpec aes = new KTSParameterSpec.Builder("AES", 256).build();
        KEM.Encapsulated enc = KEM.getInstance(KEM_NAME, "BCPQC")
            .newEncapsulator(kp.getPublic(), aes, null).encapsulate(0, 16, "AES");
        KEM.Decapsulator d = KEM.getInstance(KEM_NAME, "BCPQC").newDecapsulator(kp.getPrivate(), aes);

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

    public void testGuards()
        throws Exception
    {
        KeyPair kp = keyPair();
        KEM kem = KEM.getInstance(KEM_NAME, "BCPQC");

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

        KEM.Encapsulator e = kem.newEncapsulator(kp.getPublic(), null, null);
        KEM.Encapsulated enc = e.encapsulate();
        KEM.Decapsulator d = kem.newDecapsulator(kp.getPrivate(), null);

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
            d.decapsulate(null);
            fail("decapsulate accepted a null encapsulation");
        }
        catch (NullPointerException expected)
        {
        }
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
     * javax.crypto.KEM requires a Decapsulator to be safe for concurrent use. NTRUPlusEngine keeps one SHAKE instance in a field, so the
     * decapsulator builds its extractor per call; sharing one returned wrong secrets.
     */
    public void testConcurrentDecapsulation()
        throws Exception
    {
        final KeyPair kp = keyPair();

        final int count = 16;
        final byte[][] encapsulations = new byte[count][];
        final byte[][] expected = new byte[count][];

        KEM.Encapsulator e = KEM.getInstance(KEM_NAME, "BCPQC").newEncapsulator(kp.getPublic(), null, null);
        for (int i = 0; i != count; i++)
        {
            KEM.Encapsulated enc = e.encapsulate();
            encapsulations[i] = enc.encapsulation();
            expected[i] = enc.key().getEncoded();
        }

        final KEM.Decapsulator d = KEM.getInstance(KEM_NAME, "BCPQC").newDecapsulator(kp.getPrivate(), null);
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

    /**
     * Every parameter-set locked service is registered, is distinct from the unrestricted one and
     * from its siblings, and its object identifier resolves to the same class - the invariant a
     * copy-paste registration block can break silently. Needs no key generation.
     */
    public void testAllLockedServicesRegistered()
        throws Exception
    {
        Provider bcpqc = Security.getProvider("BCPQC");

        String unrestricted = bcpqc.getService("KEM", KEM_NAME).getClassName();
        Set<String> seen = new HashSet<String>();

        for (int i = 0; i != SPEC_NAMES.length; i++)
        {
            String name = SPEC_NAMES[i];

            Provider.Service byName = bcpqc.getService("KEM", name);
            assertNotNull("no KEM service for " + name, byName);
            assertFalse(name + " resolved to the unrestricted service",
                unrestricted.equals(byName.getClassName()));
            assertTrue(name + " shares a class with an earlier set: " + byName.getClassName(),
                seen.add(byName.getClassName()));

            Provider.Service byOid = bcpqc.getService("KEM", OIDS[i].getId());
            assertNotNull("no KEM service for OID " + OIDS[i].getId(), byOid);
            assertEquals(name + " OID resolves elsewhere",
                byName.getClassName(), byOid.getClassName());
        }
    }

    /**
     * A locked service accepts a key of its own set only.
     */
    public void testParameterSetLock()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KPG_NAME, "BCPQC");
        kpg.initialize(SPECS[0], new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        kpg.initialize(SPECS[1], new SecureRandom());
        KeyPair other = kpg.generateKeyPair();

        KEM locked = KEM.getInstance(SPEC_NAMES[0], "BCPQC");
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
    }

    /**
     * The from/to slice is honoured and is the length asked for. Worth asserting per family: a
     * helper that ignored the range would still hand both sides the same bytes, so a test that only
     * compares the two sides to each other cannot see it.
     */
    public void testSecretSlice()
        throws Exception
    {
        KeyPair kp = keyPair();
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256).build();

        KEM.Encapsulator e = KEM.getInstance(KEM_NAME, "BCPQC").newEncapsulator(kp.getPublic(), spec, null);
        KEM.Encapsulated enc = e.encapsulate(0, 16, "AES");
        assertEquals(16, enc.key().getEncoded().length);

        KEM.Decapsulator d = KEM.getInstance(KEM_NAME, "BCPQC").newDecapsulator(kp.getPrivate(), spec);
        SecretKey secR = d.decapsulate(enc.encapsulation(), 0, 16, "AES");
        assertEquals(16, secR.getEncoded().length);
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));

        // a later, non-zero window is also honoured, and differs from the leading one
        SecretKey tail = d.decapsulate(enc.encapsulation(), 16, 32, "AES");
        assertEquals(16, tail.getEncoded().length);
        assertFalse(Arrays.areEqual(secR.getEncoded(), tail.getEncoded()));
    }

    private void performKEM(String label, KeyPair kp, KTSParameterSpec spec)
        throws Exception
    {
        KEM.Encapsulator e = KEM.getInstance(KEM_NAME, "BCPQC").newEncapsulator(kp.getPublic(), spec, null);
        KEM.Encapsulated enc = e.encapsulate();
        KEM.Decapsulator d = KEM.getInstance(KEM_NAME, "BCPQC").newDecapsulator(kp.getPrivate(), spec);
        SecretKey secR = d.decapsulate(enc.encapsulation());

        assertEquals(label, enc.key().getAlgorithm(), secR.getAlgorithm());
        assertTrue(label, Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));
    }

    private static final NTRUPlusParameterSpec[] SPECS = new NTRUPlusParameterSpec[]{
        NTRUPlusParameterSpec.ntruplus_768,
        NTRUPlusParameterSpec.ntruplus_864,
        NTRUPlusParameterSpec.ntruplus_1152
    };

    private static final String[] SPEC_NAMES = {"NTRU+KEM768", "NTRU+KEM864", "NTRU+KEM1152"};

    private static final ASN1ObjectIdentifier[] OIDS = {
        org.bouncycastle.asn1.bc.BCObjectIdentifiers.ntruplus768,
        org.bouncycastle.asn1.bc.BCObjectIdentifiers.ntruplus864,
        org.bouncycastle.asn1.bc.BCObjectIdentifiers.ntruplus1152
    };
}
