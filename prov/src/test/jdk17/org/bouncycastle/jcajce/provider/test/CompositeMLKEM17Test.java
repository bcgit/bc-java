package org.bouncycastle.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.compositekem.CompositeIndex;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;

/**
 * javax.crypto.KEM API tests for Composite ML-KEM (draft-ietf-lamps-pq-composite-kem): the twelve
 * parameter sets by name and OID, the draft's test vectors through the Decapsulator, and the key checks.
 */
public class CompositeMLKEM17Test
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKEMAllParameterSets()
        throws Exception
    {
        for (ASN1ObjectIdentifier oid : CompositeIndex.getSupportedIdentifiers())
        {
            String name = CompositeIndex.getAlgorithmName(oid);

            KeyPair kp = KeyPairGenerator.getInstance(name, "BC").generateKeyPair();

            KEM.Encapsulator e = KEM.getInstance(name, "BC").newEncapsulator(kp.getPublic(), null, null);
            KEM.Encapsulated enc = e.encapsulate();

            assertEquals(name + ": secret size", 32, e.secretSize());
            assertEquals(name + ": secret length", 32, enc.key().getEncoded().length);
            assertEquals(name + ": encapsulation size", e.encapsulationSize(), enc.encapsulation().length);

            // by OID on the receiving side
            KEM.Decapsulator d = KEM.getInstance(oid.getId(), "BC").newDecapsulator(kp.getPrivate(), null);

            assertEquals(name + ": decapsulator secret size", e.secretSize(), d.secretSize());
            assertEquals(name + ": decapsulator encapsulation size", e.encapsulationSize(), d.encapsulationSize());
            assertTrue(name + ": shared secret", Arrays.areEqual(enc.key().getEncoded(), d.decapsulate(enc.encapsulation()).getEncoded()));

            // and the draft name aliases where there are any
            String[] aliases = CompositeIndex.getAlgorithmAliases(oid);
            for (int i = 0; i != aliases.length; i++)
            {
                assertNotNull(aliases[i], KEM.getInstance(aliases[i], "BC"));
            }
        }
    }

    /**
     * Decapsulating the draft's published ciphertexts through the KEM API gives the published shared
     * secrets (no KDF), and a fresh encapsulation has the published ciphertext length.
     */
    public void testDraftVectors()
        throws Exception
    {
        List<CompositeMLKEMTest.TestVector> vectors = CompositeMLKEMTest.TestVector.parse(
            TestResourceFinder.findTestResource("pqc/crypto/compositekem", "testvectors.json"));

        int checked = 0;
        for (CompositeMLKEMTest.TestVector tv : vectors)
        {
            if (tv.tcId.startsWith("id-alg-ml-kem"))
            {
                continue;
            }

            String name = tv.tcId.substring("id-".length());
            ASN1ObjectIdentifier oid = null;
            for (ASN1ObjectIdentifier candidate : CompositeIndex.getSupportedIdentifiers())
            {
                if (CompositeIndex.getAlgorithmName(candidate).equals(name))
                {
                    oid = candidate;
                }
            }
            assertNotNull(tv.tcId + ": unknown parameter set", oid);

            KeyFactory keyFactory = KeyFactory.getInstance(oid.getId(), "BC");
            PublicKey pub = keyFactory.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), tv.ek).getEncoded()));
            PrivateKey priv = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(tv.dk_pkcs8));

            KEM.Decapsulator d = KEM.getInstance(name, "BC").newDecapsulator(priv, null);
            assertEquals(tv.tcId + ": encapsulation size", tv.c.length, d.encapsulationSize());
            assertTrue(tv.tcId + ": shared secret", Arrays.areEqual(tv.k, d.decapsulate(tv.c).getEncoded()));

            KEM.Encapsulator e = KEM.getInstance(name, "BC").newEncapsulator(pub, null, new SecureRandom());
            assertEquals(tv.tcId + ": encapsulator size", tv.c.length, e.encapsulationSize());
            KEM.Encapsulated enc = e.encapsulate();
            assertEquals(tv.tcId + ": fresh encapsulation length", tv.c.length, enc.encapsulation().length);
            assertTrue(tv.tcId + ": fresh round trip", Arrays.areEqual(enc.key().getEncoded(), d.decapsulate(enc.encapsulation()).getEncoded()));

            checked++;
        }

        assertEquals("composite vectors", 12, checked);
    }

    public void testKeyChecks()
        throws Exception
    {
        String name = CompositeIndex.getAlgorithmName(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256);
        KEM kem = KEM.getInstance(name, "BC");

        // a plain ML-KEM key is not a composite key
        KeyPairGenerator mlkemGen = KeyPairGenerator.getInstance("ML-KEM", "BC");
        mlkemGen.initialize(MLKEMParameterSpec.ml_kem_768);
        KeyPair mlkem = mlkemGen.generateKeyPair();
        try
        {
            kem.newEncapsulator(mlkem.getPublic(), null, null);
            fail("ML-KEM public key accepted");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("unsupported key type", e.getMessage());
        }
        try
        {
            kem.newDecapsulator(mlkem.getPrivate(), null);
            fail("ML-KEM private key accepted");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("unsupported key type", e.getMessage());
        }

        // a composite key of another parameter set is not accepted by a named service
        KeyPair other = KeyPairGenerator.getInstance(CompositeIndex.getAlgorithmName(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256), "BC").generateKeyPair();
        try
        {
            kem.newEncapsulator(other.getPublic(), null, null);
            fail("composite key of another parameter set accepted");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("key is not a " + name + " key", e.getMessage());
        }
        try
        {
            kem.newDecapsulator(other.getPrivate(), null);
            fail("composite key of another parameter set accepted");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("key is not a " + name + " key", e.getMessage());
        }
    }

    public void testKDFAndSlices()
        throws Exception
    {
        String name = CompositeIndex.getAlgorithmName(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256);
        KeyPair kp = KeyPairGenerator.getInstance(name, "BC").generateKeyPair();

        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256).build();

        KEM.Encapsulator e = KEM.getInstance(name, "BC").newEncapsulator(kp.getPublic(), spec, new SecureRandom());
        KEM.Encapsulated enc = e.encapsulate(0, 16, "AES");

        assertEquals("AES", enc.key().getAlgorithm());
        assertEquals(16, enc.key().getEncoded().length);
        assertEquals(1568 + 97, enc.encapsulation().length);

        KEM.Decapsulator d = KEM.getInstance(name, "BC").newDecapsulator(kp.getPrivate(), spec);
        assertTrue(Arrays.areEqual(enc.key().getEncoded(), d.decapsulate(enc.encapsulation(), 0, 16, "AES").getEncoded()));

        try
        {
            d.decapsulate(Arrays.copyOf(enc.encapsulation(), enc.encapsulation().length - 1));
            fail("short encapsulation accepted");
        }
        catch (DecapsulateException ex)
        {
            assertEquals("incorrect encapsulation size", ex.getMessage());
        }

        // a corrupted ML-KEM component still decapsulates (implicit rejection) but to a different secret
        byte[] corrupted = Arrays.clone(enc.encapsulation());
        corrupted[10] ^= 1;
        assertFalse(Arrays.areEqual(enc.key().getEncoded(), d.decapsulate(corrupted, 0, 16, "AES").getEncoded()));

        // a corrupted EC component is an invalid point, reported as a DecapsulateException
        byte[] badPoint = Arrays.clone(enc.encapsulation());
        badPoint[1568 + 5] ^= 1;
        try
        {
            d.decapsulate(badPoint);
            fail("invalid EC point accepted");
        }
        catch (DecapsulateException ex)
        {
            // expected
        }
    }
}
