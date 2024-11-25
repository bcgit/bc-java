package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * KeyFactory/KeyPairGenerator tests for MLDSA with BC provider.
 */
public class MLDSAKeyPairGeneratorTest
        extends MainProvKeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKeyFactory()
            throws Exception
    {
        kf = KeyFactory.getInstance("ML-DSA", "BC");
        kf = KeyFactory.getInstance("HASH-ML-DSA", "BC");
    }

    public void testKeyPairGeneratorNames()
            throws Exception
    {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[] {
                NISTObjectIdentifiers.id_ml_dsa_44,
                NISTObjectIdentifiers.id_ml_dsa_65,
                NISTObjectIdentifiers.id_ml_dsa_87,
                NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512,
                NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512,
                NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512,
        };

        String[] algs = new String[]{
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "ML-DSA-44-WITH-SHA512",
                "ML-DSA-65-WITH-SHA512",
                "ML-DSA-87-WITH-SHA512"
        };

        for (int i = 0; i != oids.length; i++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(oids[i].getId(), "BC");

            KeyPair kp = kpGen.generateKeyPair();

            assertEquals(algs[i], kp.getPrivate().getAlgorithm());
            assertEquals(algs[i], kp.getPublic().getAlgorithm());
        }

        //
        // a bit of a cheat as we just look for "getName()" on the parameter spec.
        //
        for (int i = 0; i != algs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algs[i], "BC");
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toLowerCase(algs[i])));
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toUpperCase(algs[i])));
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toLowerCase(algs[i])), new SecureRandom());
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toUpperCase(algs[i])), new SecureRandom());
        }

        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algs[0], "BC");
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toLowerCase("Not Valid")));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("unknown parameter set name: NOT VALID", e.getMessage());
        }
    }

    public void testKeyPairEncoding()
            throws Exception
    {
        MLDSAParameterSpec[] params =
                new MLDSAParameterSpec[]
                {
                        MLDSAParameterSpec.ml_dsa_44,
                        MLDSAParameterSpec.ml_dsa_65,
                        MLDSAParameterSpec.ml_dsa_87,
                        MLDSAParameterSpec.ml_dsa_44_with_sha512,
                        MLDSAParameterSpec.ml_dsa_65_with_sha512,
                        MLDSAParameterSpec.ml_dsa_87_with_sha512,
                };

        // expected object identifiers
        ASN1ObjectIdentifier[] oids =
                {
                        NISTObjectIdentifiers.id_ml_dsa_44,
                        NISTObjectIdentifiers.id_ml_dsa_65,
                        NISTObjectIdentifiers.id_ml_dsa_87,
                        NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512,
                        NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512,
                        NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512,
                };

        //
        // We use HASH here as (while not recommended) use of both pure and pre-hash keys allowed
        kf = KeyFactory.getInstance("HASH-ML-DSA", "BC");

        kpg = KeyPairGenerator.getInstance("HASH-ML-DSA", "BC");

        for (int i = 0; i != params.length; i++)
        {
            kpg.initialize(params[i], new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            performKeyPairEncodingTest(keyPair);
            performKeyPairEncodingTest(params[i].getName(), keyPair);
            performKeyPairEncodingTest(oids[i].getId(), keyPair);
            assertNotNull(((MLDSAPrivateKey)keyPair.getPrivate()).getParameterSpec());
            assertNotNull(((MLDSAPublicKey)keyPair.getPublic()).getParameterSpec());
            assertEquals(oids[i], SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
            assertTrue(oids[i].toString(), Arrays.areEqual(((MLDSAPublicKey)keyPair.getPublic()).getPublicData(), ((MLDSAPrivateKey)keyPair.getPrivate()).getPublicKey().getPublicData()));
        }
    }

    public void testKeyParameterSpec()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");

        KeyPair kp = kpg.generateKeyPair();

        MLDSAPrivateKeySpec privSpec = (MLDSAPrivateKeySpec)kFact.getKeySpec(kp.getPrivate(), MLDSAPrivateKeySpec.class);

        assertTrue(privSpec.isSeed());

        MLDSAPrivateKey privKey = (MLDSAPrivateKey)kFact.generatePrivate(privSpec);
        
        assertEquals(privKey, kp.getPrivate());
        assertEquals(privKey.getPublicKey(), kp.getPublic());

        privSpec = new MLDSAPrivateKeySpec(privKey.getParameterSpec(), privKey.getPrivateData(), privKey.getPublicKey().getPublicData());

        assertTrue(!privSpec.isSeed());

        privKey = (MLDSAPrivateKey)kFact.generatePrivate(privSpec);

        assertEquals(privKey, kp.getPrivate());
        assertEquals(privKey.getPublicKey(), kp.getPublic());

        MLDSAPublicKeySpec pubSpec = new MLDSAPublicKeySpec(privKey.getParameterSpec(), privKey.getPublicKey().getPublicData());

        PublicKey pubKey = kFact.generatePublic(pubSpec);

        assertEquals(kp.getPublic(), pubKey);

        pubSpec = (MLDSAPublicKeySpec)kFact.getKeySpec(kp.getPrivate(), MLDSAPublicKeySpec.class);

        pubKey = kFact.generatePublic(pubSpec);

        assertEquals(kp.getPublic(), pubKey);

        pubSpec = (MLDSAPublicKeySpec)kFact.getKeySpec(kp.getPublic(), MLDSAPublicKeySpec.class);

        pubKey = kFact.generatePublic(pubSpec);

        assertEquals(kp.getPublic(), pubKey);

        privSpec = new MLDSAPrivateKeySpec(privKey.getParameterSpec(), privKey.getPrivateData(), null);

        privKey = (MLDSAPrivateKey)kFact.generatePrivate(privSpec);

        assertNotNull(privKey.getPublicKey());
    }
}
