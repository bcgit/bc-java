package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.KeyGenerator;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec;
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

    // The registered algorithm name is the tcId with the "id-" prefix dropped and the
    // "brainpoolPNNNr1" component spelled "BPNNN", matching CompositeIndex.
    private static String algorithmNameFor(String tcId)
    {
        String name = tcId.substring("id-".length());
        name = name.replace("ECDH-brainpoolP256r1", "ECDH-BP256");
        name = name.replace("ECDH-brainpoolP384r1", "ECDH-BP384");
        return name;
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
