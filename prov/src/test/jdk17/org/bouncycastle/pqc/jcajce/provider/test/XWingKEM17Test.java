package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KEM;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * javax.crypto.KEM API tests for X-Wing (draft-connolly-cfrg-xwing-kem-11) - {@code KEM.X-WING}.
 */
public class XWingKEM17Test
    extends TestCase
{
    private static final byte[] SEED = Hex.decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    private static final byte[] ESEED = Hex.decode("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2");
    private static final byte[] SS = Hex.decode("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384");

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
        KeyPairGenerator g = KeyPairGenerator.getInstance("X-WING", "BC");
        KeyPair kp = g.generateKeyPair();

        KEM kemS = KEM.getInstance("X-WING", "BC");
        KEM.Encapsulator e = kemS.newEncapsulator(kp.getPublic(), null, null);
        KEM.Encapsulated enc = e.encapsulate();

        assertEquals(1120, e.encapsulationSize());
        assertEquals(1120, enc.encapsulation().length);
        assertEquals(32, e.secretSize());

        KEM kemR = KEM.getInstance(BCObjectIdentifiers.xwing.getId(), "BC");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), null);
        SecretKey secR = d.decapsulate(enc.encapsulation());

        assertEquals(e.secretSize(), d.secretSize());
        assertEquals(e.encapsulationSize(), d.encapsulationSize());
        assertEquals(enc.key().getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), secR.getEncoded()));
    }

    /**
     * With no KDF the KEM API secret is X-Wing's own shared secret: the draft's Appendix C vector
     * comes out of the encapsulator and decapsulator, and the KeyGenerator bridge agrees.
     */
    public void testDraftVector()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("X-WING", "BC");
        g.initialize(256, new FixedSecureRandom(SEED));
        KeyPair kp = g.generateKeyPair();

        KEM.Encapsulator e = KEM.getInstance("X-WING", "BC").newEncapsulator(kp.getPublic(), null, new FixedSecureRandom(ESEED));
        KEM.Encapsulated enc = e.encapsulate();

        assertTrue(Arrays.areEqual(SS, enc.key().getEncoded()));

        KEM.Decapsulator d = KEM.getInstance("X-WING", "BC").newDecapsulator(kp.getPrivate(), null);
        assertTrue(Arrays.areEqual(SS, d.decapsulate(enc.encapsulation()).getEncoded()));

        KeyGenerator decapsulator = KeyGenerator.getInstance("X-WING", "BC");
        decapsulator.init(new KEMExtractSpec.Builder(kp.getPrivate(), enc.encapsulation(), "AES", 256).withNoKdf().build());
        SecretKeyWithEncapsulation viaKeyGenerator = (SecretKeyWithEncapsulation)decapsulator.generateKey();
        assertTrue(Arrays.areEqual(SS, viaKeyGenerator.getEncoded()));
    }

    public void testKDFAndSlices()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("X-WING", "BC");
        KeyPair kp = g.generateKeyPair();

        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256).build();

        KEM.Encapsulator e = KEM.getInstance("X-WING", "BC").newEncapsulator(kp.getPublic(), spec, new SecureRandom());
        KEM.Encapsulated enc = e.encapsulate(0, 16, "AES");

        assertEquals("AES", enc.key().getAlgorithm());
        assertEquals(16, enc.key().getEncoded().length);

        KEM.Decapsulator d = KEM.getInstance("X-WING", "BC").newDecapsulator(kp.getPrivate(), spec);
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), d.decapsulate(enc.encapsulation(), 0, 16, "AES").getEncoded()));

        try
        {
            d.decapsulate(Arrays.copyOf(enc.encapsulation(), 1119));
            fail("short encapsulation accepted");
        }
        catch (javax.crypto.DecapsulateException ex)
        {
            assertEquals("incorrect encapsulation size", ex.getMessage());
        }
    }
}
