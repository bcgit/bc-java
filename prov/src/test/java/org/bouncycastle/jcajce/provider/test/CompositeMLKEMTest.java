package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import javax.crypto.spec.SecretKeySpec;
import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

/**
 * Verifies the Composite ML-KEM implementation against the Appendix F test vectors of
 * draft-ietf-lamps-pq-composite-kem. The same vectors are published twice in bc-test-data: with
 * single-line base64 ({@code testvectors.json}) and with the base64 line-wrapped inside the JSON
 * string values ({@code testvectors_wrapped.json}); both are exercised here.
 */
public class CompositeMLKEMTest
    extends TestCase
{
    private static final String HOME_DIR = "pqc/crypto/compositekem";

    // tcId -> algorithm OID, covering the two pure ML-KEM cases and the twelve composite parameter sets.
    private static final Map<String, String> OIDS = new HashMap<String, String>();

    static
    {
        OIDS.put("id-alg-ml-kem-768", "2.16.840.1.101.3.4.4.2");
        OIDS.put("id-alg-ml-kem-1024", "2.16.840.1.101.3.4.4.3");

        OIDS.put("id-MLKEM768-RSA2048-SHA3-256", "1.3.6.1.5.5.7.6.55");
        OIDS.put("id-MLKEM768-RSA3072-SHA3-256", "1.3.6.1.5.5.7.6.56");
        OIDS.put("id-MLKEM768-RSA4096-SHA3-256", "1.3.6.1.5.5.7.6.57");
        OIDS.put("id-MLKEM768-X25519-SHA3-256", "1.3.6.1.5.5.7.6.58");
        OIDS.put("id-MLKEM768-ECDH-P256-SHA3-256", "1.3.6.1.5.5.7.6.59");
        OIDS.put("id-MLKEM768-ECDH-P384-SHA3-256", "1.3.6.1.5.5.7.6.60");
        OIDS.put("id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256", "1.3.6.1.5.5.7.6.61");
        OIDS.put("id-MLKEM1024-RSA3072-SHA3-256", "1.3.6.1.5.5.7.6.62");
        OIDS.put("id-MLKEM1024-ECDH-P384-SHA3-256", "1.3.6.1.5.5.7.6.63");
        OIDS.put("id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256", "1.3.6.1.5.5.7.6.64");
        OIDS.put("id-MLKEM1024-X448-SHA3-256", "1.3.6.1.5.5.7.6.65");
        OIDS.put("id-MLKEM1024-ECDH-P521-SHA3-256", "1.3.6.1.5.5.7.6.66");

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        CompositeMLKEMTest test = new CompositeMLKEMTest();
        test.testTestVectors();
        test.testWrappedTestVectors();
    }

    public void testTestVectors()
        throws Exception
    {
        runTestVectors("testvectors.json");
    }

    public void testWrappedTestVectors()
        throws Exception
    {
        runTestVectors("testvectors_wrapped.json");
    }

    /**
     * Exercises the composite ML-KEM KeyPairGenerator for every registered composite parameter set:
     * the generated key pair must be a CompositePublicKey / CompositePrivateKey carrying the
     * expected OID and two components, must round-trip through X.509/PKCS#8 encoding, and must
     * support encapsulate/decapsulate (proving the freshly generated components interoperate with
     * the composite KEM engine). Both the OID and the algorithm-name registrations are exercised.
     */
    public void testKeyPairGenerator()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        for (Map.Entry<String, String> entry : OIDS.entrySet())
        {
            String label = entry.getKey();
            if (isPureMLKEM(label))
            {
                continue;   // pure ML-KEM has its own KeyPairGenerator, not the composite one
            }

            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(entry.getValue());
            String algorithmName = algorithmNameFor(label);

            // generate once by OID and once by algorithm name to cover both registrations
            assertNotNull(label + ": no KeyPairGenerator by name", KeyPairGenerator.getInstance(algorithmName, bc));
            KeyPair kp = KeyPairGenerator.getInstance(oid.getId(), bc).generateKeyPair();

            assertTrue(label + ": public key is not a CompositePublicKey", kp.getPublic() instanceof CompositePublicKey);
            assertTrue(label + ": private key is not a CompositePrivateKey", kp.getPrivate() instanceof CompositePrivateKey);

            CompositePublicKey pub = (CompositePublicKey)kp.getPublic();
            CompositePrivateKey priv = (CompositePrivateKey)kp.getPrivate();

            assertEquals(label + ": unexpected public key OID", oid, pub.getAlgorithmIdentifier().getAlgorithm());
            assertEquals(label + ": expected two public components", 2, pub.getPublicKeys().size());
            assertEquals(label + ": expected two private components", 2, priv.getPrivateKeys().size());

            // CompositePublicKey.builder(String)/CompositePrivateKey.builder(String) must resolve the
            // composite-KEM name via CompositeUtil to the same OID.
            CompositePublicKey byName = CompositePublicKey.builder(algorithmName)
                .addPublicKey(pub.getPublicKeys().get(0))
                .addPublicKey(pub.getPublicKeys().get(1))
                .build();
            assertEquals(label + ": builder(name) resolved the wrong OID", oid, byName.getAlgorithmIdentifier().getAlgorithm());

            // github #2404: the composite KEM parameter sets are indexed separately from the
            // composite signature ones, so getAlgorithm() has to consult both indexes. Returning
            // null here breaks the standard JCA idiom exercised just below.
            assertEquals(label + ": unexpected public key algorithm name", algorithmName, pub.getAlgorithm());
            assertEquals(label + ": unexpected private key algorithm name", algorithmName, priv.getAlgorithm());

            KeyFactory byKeyName = KeyFactory.getInstance(pub.getAlgorithm(), bc);
            assertTrue(label + ": key did not round-trip through KeyFactory.getInstance(key.getAlgorithm())",
                Arrays.areEqual(pub.getEncoded(),
                    byKeyName.generatePublic(new X509EncodedKeySpec(pub.getEncoded())).getEncoded()));

            // and the SubjectPublicKeyInfo / PrivateKeyInfo constructors have to accept a composite
            // KEM key as well as a composite signature one
            CompositePublicKey fromSpki = new CompositePublicKey(SubjectPublicKeyInfo.getInstance(pub.getEncoded()));
            CompositePrivateKey fromPki = new CompositePrivateKey(PrivateKeyInfo.getInstance(priv.getEncoded()));
            assertEquals(label + ": SubjectPublicKeyInfo constructor lost the algorithm", algorithmName, fromSpki.getAlgorithm());
            assertEquals(label + ": PrivateKeyInfo constructor lost the algorithm", algorithmName, fromPki.getAlgorithm());
            assertTrue(label + ": SubjectPublicKeyInfo constructor did not round-trip",
                Arrays.areEqual(pub.getEncoded(), fromSpki.getEncoded()));
            assertTrue(label + ": PrivateKeyInfo constructor did not round-trip",
                Arrays.areEqual(priv.getEncoded(), fromPki.getEncoded()));

            // keys must round-trip through their encoded form
            KeyFactory kf = KeyFactory.getInstance(oid.getId(), bc);
            PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
            PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
            assertTrue(label + ": public key did not round-trip", Arrays.areEqual(pub.getEncoded(), pub2.getEncoded()));
            assertTrue(label + ": private key did not round-trip", Arrays.areEqual(priv.getEncoded(), priv2.getEncoded()));

            // the generated key pair must support encapsulate/decapsulate
            KeyGenerator gen = KeyGenerator.getInstance(oid.getId(), bc);
            gen.init(new KEMGenerateSpec.Builder(pub2, "AES", 256).withKdfAlgorithm(null).build(), new SecureRandom());
            SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation)gen.generateKey();

            byte[] decapsulated = decapsulate(oid, bc, priv2, enc.getEncapsulation());
            assertTrue(label + ": generated key pair failed encapsulate/decapsulate round-trip",
                Arrays.areEqual(enc.getEncoded(), decapsulated));
        }
    }

    /**
     * initialize(null, random) is documented as existing only to supply a SecureRandom, but it
     * forwarded to a component only where CompositeIndex held a non-null key-generation spec for it.
     * The ML-KEM half never had one, and for the X25519 and X448 composites neither half did, so on
     * those the caller's random reached neither component and on the rest it never reached the
     * post-quantum one. This is the composite-KEM half of the same defect fixed on the signature
     * side; see CompositeSignaturesTest.testKeyPairGeneratorSecureRandom.
     */
    public void testKeyPairGeneratorSecureRandom()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        // neither component of the XDH composites had a spec, so nothing consumed the random at all
        String[] neither = new String[]{"MLKEM768-X25519-SHA3-256", "MLKEM1024-X448-SHA3-256"};

        for (int i = 0; i != neither.length; i++)
        {
            CompositeSignaturesTest.CountingSecureRandom counting = new CompositeSignaturesTest.CountingSecureRandom();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(neither[i], bc);
            kpg.initialize(null, counting);
            kpg.generateKeyPair();

            assertTrue(neither[i] + ": supplied SecureRandom was never drawn from", counting.calls > 0);
        }

        // and across the parameter sets it has to be the only source, or the key pair would not be
        // reproducible from the seed - which is what pins the ML-KEM half of every combination
        for (Map.Entry<String, String> entry : OIDS.entrySet())
        {
            String label = entry.getKey();

            if (isPureMLKEM(label))
            {
                continue;
            }

            String algorithm = algorithmNameFor(label);

            if (algorithm.indexOf("RSA") >= 0)
            {
                continue;       // an RSA prime search draws an unbounded, seed-dependent amount
            }

            KeyPairGenerator first = KeyPairGenerator.getInstance(algorithm, bc);
            first.initialize(null, new CompositeSignaturesTest.SeededSecureRandom(11));

            KeyPairGenerator second = KeyPairGenerator.getInstance(algorithm, bc);
            second.initialize(null, new CompositeSignaturesTest.SeededSecureRandom(11));

            assertTrue(algorithm + ": key pair not determined by the supplied SecureRandom",
                Arrays.areEqual(first.generateKeyPair().getPublic().getEncoded(),
                    second.generateKeyPair().getPublic().getEncoded()));
        }
    }

    /**
     * The SupportedKeyClasses / SupportedKeyFormats maps were built and then never passed to a
     * provider registration, so JCA key-class filtering did not work for any composite KEM service.
     */
    public void testServiceAttributesPublished()
        throws Exception
    {
        Provider prov = Security.getProvider("BC");

        String[] types = new String[]{"Cipher", "KeyGenerator"};

        for (int i = 0; i != types.length; i++)
        {
            Provider.Service service = prov.getService(types[i], "MLKEM768-ECDH-P256-SHA3-256");

            assertNotNull(types[i], service);
            assertEquals(types[i],
                "org.bouncycastle.jcajce.CompositePublicKey|org.bouncycastle.jcajce.CompositePrivateKey",
                service.getAttribute("SupportedKeyClasses"));
            assertEquals(types[i], "PKCS#8|X.509", service.getAttribute("SupportedKeyFormats"));
        }
    }

    /**
     * A wrapped key shorter than the composite encapsulation was not rejected: BC's
     * Arrays.copyOfRange zero-pads a range running off the end, so the decapsulation ran on a padded
     * encapsulation - which ML-KEM's implicit rejection makes succeed - and the failure surfaced
     * from the AES-KWP unwrap instead, naming the wrong thing.
     */
    public void testShortCiphertextRejected()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        String name = "MLKEM768-ECDH-P256-SHA3-256";

        KeyPair kp = KeyPairGenerator.getInstance(name, bc).generateKeyPair();
        SecretKeySpec toWrap = new SecretKeySpec(new byte[32], "AES");

        Cipher wrapper = Cipher.getInstance(name, bc);
        wrapper.init(Cipher.WRAP_MODE, kp.getPublic());

        byte[] wrapped = wrapper.wrap(toWrap);

        Cipher unwrapper = Cipher.getInstance(name, bc);
        unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate());

        assertTrue("the unmodified wrap must still round-trip", Arrays.areEqual(toWrap.getEncoded(),
            unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded()));

        try
        {
            unwrapper.unwrap(new byte[10], "AES", Cipher.SECRET_KEY);
            fail("ciphertext shorter than the encapsulation accepted");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("malformed composite KEM ciphertext: shorter than the encapsulation", e.getMessage());
        }
    }

    /**
     * Decapsulation through a KeyGenerator with a KEMExtractSpec only required the ciphertext to be
     * at least as long as the ML-KEM part, so a traditional part in a second encoding decapsulated,
     * to a key the sender did not hold: an X25519 or X448 value wrapped in a SubjectPublicKeyInfo
     * under any algorithm identifier, and an RSA-OAEP value with its leading zero octet dropped.
     * Sections 3.3 and 4 of draft-ietf-lamps-pq-composite-kem give each component ciphertext one
     * encoding, of fixed length.
     */
    public void testNonCanonicalCiphertextRejected()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");
        ASN1ObjectIdentifier x25519 = new ASN1ObjectIdentifier("1.3.101.110");
        ASN1ObjectIdentifier x448 = new ASN1ObjectIdentifier("1.3.101.111");
        AlgorithmIdentifier rsaEncryption = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), DERNull.INSTANCE);

        String[] names = {"MLKEM768-X25519-SHA3-256", "MLKEM1024-X448-SHA3-256", "MLKEM768-RSA2048-SHA3-256", "MLKEM768-ECDH-P256-SHA3-256"};

        for (int i = 0; i != names.length; i++)
        {
            String name = names[i];
            int m = name.startsWith("MLKEM768") ? 1088 : 1568;
            boolean isRSA = name.indexOf("RSA") > 0;

            KeyPair kp = KeyPairGenerator.getInstance(name, bc).generateKeyPair();

            // for RSA, encapsulate until the RSA-OAEP part has a leading zero octet (about 1 in 256)
            byte[] ct;
            byte[] ss;
            int tries = 0;
            do
            {
                KeyGenerator gen = KeyGenerator.getInstance(name, bc);
                gen.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 256).withKdfAlgorithm(null).build(), new SecureRandom());
                SecretKeyWithEncapsulation k = (SecretKeyWithEncapsulation)gen.generateKey();
                ct = k.getEncapsulation();
                ss = k.getEncoded();
            }
            while (isRSA && ct[m] != 0 && ++tries < 20000);

            byte[] mlkemCT = Arrays.copyOfRange(ct, 0, m);
            byte[] tradCT = Arrays.copyOfRange(ct, m, ct.length);

            assertTrue(name + ": the unmodified ciphertext must still decapsulate", Arrays.areEqual(ss, extract(name, kp.getPrivate(), ct)));

            List<byte[]> malformed = new ArrayList<byte[]>();

            if (isRSA)
            {
                assertEquals(name + ": no RSA-OAEP ciphertext with a leading zero found", 0, tradCT[0]);
                malformed.add(Arrays.copyOfRange(tradCT, 1, tradCT.length));
            }
            else if (name.indexOf("ECDH") < 0)
            {
                malformed.add(new SubjectPublicKeyInfo(new AlgorithmIdentifier(x25519), tradCT).getEncoded("DER"));
                malformed.add(new SubjectPublicKeyInfo(new AlgorithmIdentifier(x448), tradCT).getEncoded("DER"));
                malformed.add(new SubjectPublicKeyInfo(rsaEncryption, tradCT).getEncoded("DER"));
            }
            // these were rejected before the length was checked, but each for a different reason
            malformed.add(Arrays.append(tradCT, (byte)0));
            malformed.add(Arrays.copyOfRange(tradCT, 0, tradCT.length - 1));
            malformed.add(Arrays.prepend(tradCT, (byte)0));

            for (int j = 0; j != malformed.size(); j++)
            {
                byte[] t = (byte[])malformed.get(j);

                try
                {
                    extract(name, kp.getPrivate(), Arrays.concatenate(mlkemCT, t));
                    fail(name + ": traditional ciphertext of " + t.length + " octets accepted (case " + j + ")");
                }
                catch (IllegalStateException e)
                {
                    assertEquals("Decapsulation failed: malformed composite ciphertext: wrong length", e.getMessage());
                }
            }
        }
    }

    /**
     * Section 6.1 of draft-ietf-lamps-pq-composite-kem fixes the RSA modulus size of each RSA
     * composite and section 3.3 requires it to be checked, but nothing did: an RSA-1024 or RSA-3072
     * key under the MLKEM768-RSA2048 OID decoded, encapsulated and decapsulated. The KeyFactory now
     * rejects such a key, and so do encapsulation and decapsulation for a key built without it.
     */
    public void testRSAComponentSizeEnforced()
        throws Exception
    {
        String name = "MLKEM768-RSA2048-SHA3-256";
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.55");
        KeyPair mlkem = KeyPairGenerator.getInstance("ML-KEM-768", "BC").generateKeyPair();
        int[] sizes = {1024, 3072};

        for (int i = 0; i != sizes.length; i++)
        {
            KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
            rsaGen.initialize(sizes[i]);
            KeyPair rsa = rsaGen.generateKeyPair();

            CompositePublicKey pub = new CompositePublicKey(oid, mlkem.getPublic(), rsa.getPublic());
            CompositePrivateKey priv = new CompositePrivateKey(oid, mlkem.getPrivate(), rsa.getPrivate());

            KeyFactory kf = KeyFactory.getInstance(name, "BC");
            try
            {
                kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
                fail("public key with an RSA-" + sizes[i] + " component decoded");
            }
            catch (InvalidKeySpecException e)
            {
                assertTrue(e.getMessage(), e.getMessage().endsWith("malformed composite public key: RSA component must be a 2048-bit key"));
            }
            try
            {
                kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
                fail("private key with an RSA-" + sizes[i] + " component decoded");
            }
            catch (InvalidKeySpecException e)
            {
                assertTrue(e.getMessage(), e.getMessage().endsWith("malformed composite private key: RSA component must be a 2048-bit key"));
            }

            try
            {
                KeyGenerator gen = KeyGenerator.getInstance(name, "BC");
                gen.init(new KEMGenerateSpec.Builder(pub, "AES", 256).withKdfAlgorithm(null).build(), new SecureRandom());
                gen.generateKey();
                fail("encapsulated to an RSA-" + sizes[i] + " component");
            }
            catch (IllegalStateException e)
            {
                assertEquals("Encapsulation failed: Traditional encapsulation failed: RSA component must be a 2048-bit key", e.getMessage());
            }

            try
            {
                extract(name, priv, new byte[1088 + sizes[i] / 8]);
                fail("decapsulated with an RSA-" + sizes[i] + " component");
            }
            catch (IllegalStateException e)
            {
                assertEquals("Decapsulation failed: RSA component must be a 2048-bit key", e.getMessage());
            }
        }
    }

    private static byte[] extract(String name, PrivateKey priv, byte[] encapsulation)
        throws Exception
    {
        KeyGenerator gen = KeyGenerator.getInstance(name, "BC");

        gen.init(new KEMExtractSpec.Builder(priv, encapsulation, "AES", 256).withKdfAlgorithm(null).build());

        return gen.generateKey().getEncoded();
    }

    /**
     * javax.crypto.KEM.newEncapsulator() documents a null SecureRandom as a request for the
     * provider's default, and KeyGenerator.init(spec, null) reaches the composite KEM the same way.
     * The RSA-OAEP composites draw the traditional shared secret from the supplied random directly,
     * so a null one used to surface as a NullPointerException wrapped in an IllegalStateException;
     * the ECDH and XDH composites were unaffected because their component KeyPairGenerators default
     * a random themselves. One set of each is covered.
     */
    public void testNullSecureRandom()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        String[] names = new String[]{"MLKEM768-RSA2048-SHA3-256", "MLKEM768-ECDH-P256-SHA3-256", "MLKEM768-X25519-SHA3-256"};

        for (int i = 0; i != names.length; i++)
        {
            String name = names[i];
            KeyPair kp = KeyPairGenerator.getInstance(name, bc).generateKeyPair();

            KeyGenerator gen = KeyGenerator.getInstance(name, bc);
            gen.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 256).withKdfAlgorithm(null).build(), (SecureRandom)null);
            SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation)gen.generateKey();

            byte[] decapsulated = decapsulate(new ASN1ObjectIdentifier(OIDS.get("id-" + name)), bc,
                kp.getPrivate(), enc.getEncapsulation());
            assertTrue(name + ": encapsulation with a null SecureRandom did not round-trip",
                Arrays.areEqual(enc.getEncoded(), decapsulated));
        }
    }

    /**
     * Section 4 of draft-ietf-lamps-pq-composite-kem requires an EC component to be carried as an
     * uncompressed point. Encapsulation takes tradPK from the recipient key's own encoding while
     * decapsulation recomputes the point from the private key, so a component key that encodes
     * itself compressed - a BC EC key whose point format has been set, or a key from a provider
     * that preserves a compressed encoding - used to combine a different tradPK on each side and
     * the two sides silently derived different shared secrets.
     */
    public void testCompressedECComponentIsNormalised()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        String name = "MLKEM768-ECDH-P256-SHA3-256";
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(OIDS.get("id-" + name));

        KeyPair kp = KeyPairGenerator.getInstance(name, bc).generateKeyPair();
        CompositePublicKey pub = (CompositePublicKey)kp.getPublic();

        ((ECPointEncoder)pub.getPublicKeys().get(1)).setPointFormat("COMPRESSED");

        KeyGenerator gen = KeyGenerator.getInstance(name, bc);
        gen.init(new KEMGenerateSpec.Builder(pub, "AES", 256).withKdfAlgorithm(null).build(), new SecureRandom());
        SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation)gen.generateKey();

        byte[] decapsulated = decapsulate(oid, bc, kp.getPrivate(), enc.getEncapsulation());
        assertTrue(name + ": a compressed EC component must still agree on the shared secret",
            Arrays.areEqual(enc.getEncoded(), decapsulated));
    }

    /**
     * The two brainpool parameter sets were originally registered with the curve abbreviated
     * (MLKEM768-ECDH-BP256-SHA3-256); they are now registered under the draft's spelling, with the
     * short form kept as an alias, so both names resolve and both reach the same OID.
     */
    public void testBrainpoolNameAliases()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        String[][] pairs = new String[][]{
            {"MLKEM768-ECDH-brainpoolP256r1-SHA3-256", "MLKEM768-ECDH-BP256-SHA3-256"},
            {"MLKEM1024-ECDH-brainpoolP384r1-SHA3-256", "MLKEM1024-ECDH-BP384-SHA3-256"}
        };

        for (int i = 0; i != pairs.length; i++)
        {
            String draftName = pairs[i][0];
            String alias = pairs[i][1];

            KeyPair kp = KeyPairGenerator.getInstance(alias, bc).generateKeyPair();

            assertEquals(alias + ": getAlgorithm() must report the draft name", draftName, kp.getPublic().getAlgorithm());
            assertEquals(alias + ": getAlgorithm() must report the draft name", draftName, kp.getPrivate().getAlgorithm());

            assertNotNull(alias + ": no KeyPairGenerator", KeyPairGenerator.getInstance(draftName, bc));
            assertNotNull(alias + ": no KeyGenerator", KeyGenerator.getInstance(alias, bc));
            assertNotNull(alias + ": no KeyGenerator", KeyGenerator.getInstance(draftName, bc));
            assertNotNull(alias + ": no Cipher", javax.crypto.Cipher.getInstance(alias, bc));
            assertNotNull(alias + ": no Cipher", javax.crypto.Cipher.getInstance(draftName, bc));

            // both names must resolve to the same key, through the KeyFactory each of them aliases
            assertTrue(alias + ": KeyFactory did not round-trip",
                Arrays.areEqual(kp.getPublic().getEncoded(), KeyFactory.getInstance(alias, bc)
                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())).getEncoded()));
            assertTrue(draftName + ": KeyFactory did not round-trip",
                Arrays.areEqual(kp.getPublic().getEncoded(), KeyFactory.getInstance(draftName, bc)
                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())).getEncoded()));

            // CompositePublicKey.builder(String) resolves either spelling to the same OID
            ASN1ObjectIdentifier oid = ((CompositePublicKey)kp.getPublic()).getAlgorithmIdentifier().getAlgorithm();
            assertEquals(alias + ": builder(alias) resolved the wrong OID", oid,
                CompositePublicKey.builder(alias).addPublicKey(((CompositePublicKey)kp.getPublic()).getPublicKeys().get(0))
                    .addPublicKey(((CompositePublicKey)kp.getPublic()).getPublicKeys().get(1)).build()
                    .getAlgorithmIdentifier().getAlgorithm());
            assertEquals(draftName + ": builder(name) resolved the wrong OID", oid,
                CompositePublicKey.builder(draftName).addPublicKey(((CompositePublicKey)kp.getPublic()).getPublicKeys().get(0))
                    .addPublicKey(((CompositePublicKey)kp.getPublic()).getPublicKeys().get(1)).build()
                    .getAlgorithmIdentifier().getAlgorithm());
        }
    }

    /**
     * CompositePublicKey.getEncoded() now normalises an EC component to an uncompressed point, as
     * section 4 of the draft requires. That is a write-side change only: a composite KEM public key
     * that an earlier release wrote with a compressed EC component - the shorter body assembled by
     * hand here - must still decode, and encapsulating to the key it decodes to must still agree
     * with the matching private key.
     */
    public void testCompressedECComponentStillDecodes()
        throws Exception
    {
        Provider bc = Security.getProvider("BC");

        String name = "MLKEM768-ECDH-P256-SHA3-256";
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(OIDS.get("id-" + name));

        KeyPair kp = KeyPairGenerator.getInstance(name, bc).generateKeyPair();
        CompositePublicKey pub = (CompositePublicKey)kp.getPublic();

        byte[] mlkemPK = SubjectPublicKeyInfo.getInstance(pub.getPublicKeys().get(0).getEncoded()).getPublicKeyData().getOctets();

        PublicKey ecPub = pub.getPublicKeys().get(1);
        ((ECPointEncoder)ecPub).setPointFormat("COMPRESSED");
        byte[] compressedEC = SubjectPublicKeyInfo.getInstance(ecPub.getEncoded()).getPublicKeyData().getOctets();
        assertEquals("EC component should be a compressed point", 33, compressedEC.length);

        SubjectPublicKeyInfo legacy = new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid),
            Arrays.concatenate(mlkemPK, compressedEC));

        PublicKey decoded = KeyFactory.getInstance(oid.getId(), bc)
            .generatePublic(new X509EncodedKeySpec(legacy.getEncoded()));

        KeyGenerator gen = KeyGenerator.getInstance(name, bc);
        gen.init(new KEMGenerateSpec.Builder(decoded, "AES", 256).withKdfAlgorithm(null).build(), new SecureRandom());
        SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation)gen.generateKey();

        byte[] decapsulated = decapsulate(oid, bc, kp.getPrivate(), enc.getEncapsulation());
        assertTrue(name + ": a key decoded from a compressed EC component must still agree on the shared secret",
            Arrays.areEqual(enc.getEncoded(), decapsulated));
    }

    // The registered algorithm name is the tcId with the "id-" prefix dropped.
    private static String algorithmNameFor(String tcId)
    {
        return tcId.substring("id-".length());
    }

    private void runTestVectors(String fileName)
        throws Exception
    {
        List<TestVector> vectors = TestVector.parse(TestResourceFinder.findTestResource(HOME_DIR, fileName));

        assertEquals(fileName + ": unexpected number of test cases", 14, vectors.size());

        Provider bc = Security.getProvider("BC");

        for (int i = 0; i != vectors.size(); i++)
        {
            TestVector tv = vectors.get(i);
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidFor(tv.tcId));

            if (isPureMLKEM(tv.tcId))
            {
                checkPureMLKEM(tv, oid, bc);
            }
            else
            {
                checkComposite(tv, oid, bc, false);
                checkComposite(tv, oid, bc, true);
            }
        }
    }

    /**
     * Exercises a composite parameter set: parse the published keys, optionally rebuild them from
     * their components with explicit providers (the {@code mixedProviders} case), check the encodings
     * round-trip, and confirm that decapsulating the published ciphertext yields the published secret.
     */
    private void checkComposite(TestVector tv, ASN1ObjectIdentifier oid, Provider bc, boolean mixedProviders)
        throws Exception
    {
        String label = tv.tcId + (mixedProviders ? " (mixed providers)" : "");

        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), tv.ek);

        KeyFactory keyFactory = KeyFactory.getInstance(oid.getId(), "BC");
        CompositePublicKey compositePub = (CompositePublicKey)keyFactory.generatePublic(new X509EncodedKeySpec(pubInfo.getEncoded()));
        CompositePrivateKey compositePriv = (CompositePrivateKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(tv.dk_pkcs8));

        assertEquals(label + ": composite key must have 2 components", 2, compositePub.getPublicKeys().size());

        // the encodings must reproduce the published key material exactly
        assertTrue(label + ": private key did not round-trip", Arrays.areEqual(compositePriv.getEncoded(), tv.dk_pkcs8));
        assertTrue(label + ": public key did not round-trip", Arrays.areEqual(compositePub.getEncoded(), pubInfo.getEncoded()));

        // the published certificate's public key must decode (through the BC key-info converter) to the same key
        X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(tv.x5c));
        PublicKey certPub = cert.getPublicKey();
        assertTrue(label + ": certificate public key is not a CompositePublicKey", certPub instanceof CompositePublicKey);
        assertTrue(label + ": certificate public key did not match", Arrays.areEqual(certPub.getEncoded(), pubInfo.getEncoded()));

        PublicKey pubKey;
        PrivateKey privKey;
        if (mixedProviders)
        {
            // rebuild the composite keys pinning the BC provider on the ML-KEM component, exercising the
            // provider-aware encapsulation/decapsulation path.
            CompositePublicKey.Builder pubBuilder = CompositePublicKey.builder(oid);
            pubBuilder.addPublicKey(compositePub.getPublicKeys().get(0), bc);
            pubBuilder.addPublicKey(compositePub.getPublicKeys().get(1));
            pubKey = pubBuilder.build();

            CompositePrivateKey.Builder privBuilder = CompositePrivateKey.builder(oid);
            privBuilder.addPrivateKey(compositePriv.getPrivateKeys().get(0), bc);
            privBuilder.addPrivateKey(compositePriv.getPrivateKeys().get(1));
            privKey = privBuilder.build();
        }
        else
        {
            pubKey = compositePub;
            privKey = compositePriv;
        }

        checkEncapsulation(label, oid, bc, pubKey, privKey, tv.c, tv.k);
    }

    /**
     * Exercises a pure ML-KEM parameter set (the {@code id-alg-ml-kem-*} vectors) so the file is fully
     * covered and the composite plumbing shares the same shared-secret check.
     */
    private void checkPureMLKEM(TestVector tv, ASN1ObjectIdentifier oid, Provider bc)
        throws Exception
    {
        MLKEMParameterSpec paramSpec = tv.tcId.contains("768") ? MLKEMParameterSpec.ml_kem_768 : MLKEMParameterSpec.ml_kem_1024;

        KeyFactory keyFactory = KeyFactory.getInstance(oid.getId(), "BC");
        PublicKey pubKey = keyFactory.generatePublic(new MLKEMPublicKeySpec(paramSpec, tv.ek));
        PrivateKey privKey = keyFactory.generatePrivate(new MLKEMPrivateKeySpec(paramSpec, tv.dk));

        checkEncapsulation(tv.tcId, oid, bc, pubKey, privKey, tv.c, tv.k);
    }

    private void checkEncapsulation(String label, ASN1ObjectIdentifier oid, Provider bc,
                                    PublicKey pubKey, PrivateKey privKey, byte[] vectorCt, byte[] vectorK)
        throws Exception
    {
        // fresh encapsulation must round-trip through decapsulation
        KeyGenerator generator = KeyGenerator.getInstance(oid.getId(), bc);
        generator.init(new KEMGenerateSpec.Builder(pubKey, "AES", 256).withKdfAlgorithm(null).build(), new SecureRandom());
        SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation)generator.generateKey();

        // the freshly produced ciphertext must be byte-length conformant with the published vector
        // (the component encodings are fixed length), so a non-conformant component encoding -
        // e.g. an SPKI-wrapped X25519/X448 ciphertext instead of the raw RFC 7748 key - is rejected.
        assertEquals(label + ": fresh encapsulation length does not match the draft ciphertext length",
            vectorCt.length, enc.getEncapsulation().length);

        byte[] roundTrip = decapsulate(oid, bc, privKey, enc.getEncapsulation());
        assertTrue(label + ": encapsulate/decapsulate produced different secrets", Arrays.areEqual(enc.getEncoded(), roundTrip));

        // decapsulating the published ciphertext must yield the published shared secret
        byte[] vectorSecret = decapsulate(oid, bc, privKey, vectorCt);
        assertTrue(label + ": decapsulated secret did not match expected k", Arrays.areEqual(vectorK, vectorSecret));
    }

    private static byte[] decapsulate(ASN1ObjectIdentifier oid, Provider bc, PrivateKey privKey, byte[] ciphertext)
        throws Exception
    {
        KeyGenerator generator = KeyGenerator.getInstance(oid.getId(), bc);
        generator.init(new KEMExtractSpec.Builder(privKey, ciphertext, "AES", 256).withKdfAlgorithm(null).build());
        return ((SecretKeyWithEncapsulation)generator.generateKey()).getEncoded();
    }

    private static boolean isPureMLKEM(String tcId)
    {
        return tcId.startsWith("id-alg-ml-kem");
    }

    private static String oidFor(String tcId)
    {
        String oid = OIDS.get(tcId);
        if (oid == null)
        {
            throw new IllegalStateException("no OID registered for test case " + tcId);
        }
        return oid;
    }

    /**
     * One Appendix F test case. {@link #parse(InputStream)} is a tolerant reader for the bc-test-data
     * JSON: it walks string literals and brace nesting, so it is unaffected by base64 that is wrapped
     * across several lines inside the JSON string values.
     */
    static class TestVector
    {
        String tcId;
        byte[] ek;       // composite / ML-KEM public (encapsulation) key
        byte[] dk;       // raw ML-KEM decapsulation key (seed form)
        byte[] dk_pkcs8; // PKCS#8 encoded private key
        byte[] c;        // ciphertext
        byte[] k;        // expected shared secret
        byte[] x5c;      // X.509 certificate carrying the public key

        static List<TestVector> parse(InputStream in)
            throws IOException
        {
            String text = Strings.fromUTF8ByteArray(Streams.readAll(in));

            List<TestVector> out = new ArrayList<TestVector>();
            TestVector current = null;
            String pendingKey = null;
            int depth = 0;

            for (int i = 0, n = text.length(); i < n; )
            {
                char ch = text.charAt(i);
                if (ch == '"')
                {
                    StringBuilder sb = new StringBuilder();
                    i++;
                    while (i < n)
                    {
                        char c = text.charAt(i);
                        if (c == '\\' && i + 1 < n)
                        {
                            sb.append(text.charAt(i + 1));
                            i += 2;
                            continue;
                        }
                        if (c == '"')
                        {
                            break;
                        }
                        sb.append(c);
                        i++;
                    }
                    i++; // consume closing quote

                    String token = sb.toString();
                    if (pendingKey == null)
                    {
                        pendingKey = token;
                    }
                    else
                    {
                        if (current != null)
                        {
                            current.set(pendingKey, token);
                        }
                        pendingKey = null;
                    }
                }
                else if (ch == '{')
                {
                    depth++;
                    if (depth >= 2)
                    {
                        current = new TestVector();
                    }
                    pendingKey = null;
                    i++;
                }
                else if (ch == '}')
                {
                    if (depth >= 2 && current != null)
                    {
                        out.add(current);
                        current = null;
                    }
                    depth--;
                    pendingKey = null;
                    i++;
                }
                else
                {
                    i++;
                }
            }

            return out;
        }

        private void set(String key, String value)
        {
            if ("tcId".equals(key))
            {
                tcId = value;
            }
            else if ("ek".equals(key))
            {
                ek = decode(value);
            }
            else if ("dk".equals(key))
            {
                dk = decode(value);
            }
            else if ("dk_pkcs8".equals(key))
            {
                dk_pkcs8 = decode(value);
            }
            else if ("c".equals(key))
            {
                c = decode(value);
            }
            else if ("k".equals(key))
            {
                k = decode(value);
            }
            else if ("x5c".equals(key))
            {
                x5c = decode(value);
            }
            // other keys (e.g. cacert) are ignored
        }

        private static byte[] decode(String base64)
        {
            // the wrapped vectors carry literal newlines inside the base64 strings
            return Base64.decode(base64.replaceAll("\\s", ""));
        }
    }
}
