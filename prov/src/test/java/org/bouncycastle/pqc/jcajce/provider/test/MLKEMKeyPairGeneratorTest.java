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
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * KeyFactory/KeyPairGenerator tests for MLKEM with BCPQC provider.
 */
public class MLKEMKeyPairGeneratorTest
    extends KeyPairGeneratorTest
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
        kf = KeyFactory.getInstance("ML-KEM", "BC");
    }

    public void testKeyPairGeneratorNames()
        throws Exception
    {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]{
            NISTObjectIdentifiers.id_alg_ml_kem_512,
            NISTObjectIdentifiers.id_alg_ml_kem_768,
            NISTObjectIdentifiers.id_alg_ml_kem_1024
        };

        String[] algs = new String[]{
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024"
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
        MLKEMParameterSpec[] params =
            new MLKEMParameterSpec[]
                {
                    MLKEMParameterSpec.ml_kem_512,
                    MLKEMParameterSpec.ml_kem_768,
                    MLKEMParameterSpec.ml_kem_1024,
                };
        // expected object identifiers
        ASN1ObjectIdentifier[] oids =
            {
                NISTObjectIdentifiers.id_alg_ml_kem_512,
                NISTObjectIdentifiers.id_alg_ml_kem_768,
                NISTObjectIdentifiers.id_alg_ml_kem_1024,
            };
        kf = KeyFactory.getInstance("ML-KEM", "BC");

        kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");

        for (int i = 0; i != params.length; i++)
        {
            kpg.initialize(params[i], new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            performKeyPairEncodingTest(keyPair);
            assertEquals(oids[i], SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
            assertTrue(oids[i].toString(), Arrays.areEqual(((MLKEMPublicKey)keyPair.getPublic()).getPublicData(), ((MLKEMPrivateKey)keyPair.getPrivate()).getPublicKey().getPublicData()));
        }
    }

    public void testKeyParameterSpec()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-512", "BC");
        KeyFactory kFact = KeyFactory.getInstance("ML-KEM", "BC");

        KeyPair kp = kpg.generateKeyPair();

        MLKEMPrivateKeySpec privSpec = (MLKEMPrivateKeySpec)kFact.getKeySpec(kp.getPrivate(), MLKEMPrivateKeySpec.class);

        assertTrue(privSpec.isSeed());

        MLKEMPrivateKey privKey = (MLKEMPrivateKey)kFact.generatePrivate(privSpec);
        
        assertEquals(privKey, kp.getPrivate());
        assertEquals(privKey.getPublicKey(), kp.getPublic());

        privSpec = new MLKEMPrivateKeySpec(privKey.getParameterSpec(), privKey.getPrivateData(), privKey.getPublicKey().getPublicData());

        assertTrue(!privSpec.isSeed());

        privKey = (MLKEMPrivateKey)kFact.generatePrivate(privSpec);

        assertEquals(privKey, kp.getPrivate());
        assertEquals(privKey.getPublicKey(), kp.getPublic());

        MLKEMPublicKeySpec pubSpec = new MLKEMPublicKeySpec(privKey.getParameterSpec(), privKey.getPublicKey().getPublicData());

        PublicKey pubKey = kFact.generatePublic(pubSpec);

        assertEquals(kp.getPublic(), pubKey);

        pubSpec = (MLKEMPublicKeySpec)kFact.getKeySpec(kp.getPrivate(), MLKEMPublicKeySpec.class);

        pubKey = kFact.generatePublic(pubSpec);

        assertEquals(kp.getPublic(), pubKey);

        pubSpec = (MLKEMPublicKeySpec)kFact.getKeySpec(kp.getPublic(), MLKEMPublicKeySpec.class);

        pubKey = kFact.generatePublic(pubSpec);

        assertEquals(kp.getPublic(), pubKey);
    }
}
