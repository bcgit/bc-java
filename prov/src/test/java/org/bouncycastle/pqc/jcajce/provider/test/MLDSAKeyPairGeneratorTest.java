package org.bouncycastle.pqc.jcajce.provider.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * KeyFactory/KeyPairGenerator tests for MLDSA with BC provider.
 */
public class MLDSAKeyPairGeneratorTest
        extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testKeyFactory()
            throws Exception
    {
        kf = KeyFactory.getInstance("ML-DSA", "BC");
    }

    public void testKeyPairGeneratorNames()
            throws Exception
    {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[] {
                NISTObjectIdentifiers.id_ml_dsa_44,
                NISTObjectIdentifiers.id_ml_dsa_65,
                NISTObjectIdentifiers.id_ml_dsa_87
        };

        String[] algs = new String[]{
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87"
        };

        for (int i = 0; i != oids.length; i++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(oids[i].getId(), "BC");

            KeyPair kp = kpGen.generateKeyPair();

            assertEquals(algs[i], kp.getPrivate().getAlgorithm());
            assertEquals(algs[i], kp.getPublic().getAlgorithm());
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
                        };

        // expected object identifiers
        ASN1ObjectIdentifier[] oids =
                {
                        NISTObjectIdentifiers.id_ml_dsa_44,
                        NISTObjectIdentifiers.id_ml_dsa_65,
                        NISTObjectIdentifiers.id_ml_dsa_87,
                };

        kf = KeyFactory.getInstance("ML-DSA", "BC");

        kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        for (int i = 0; i != params.length; i++)
        {
            kpg.initialize(params[i], new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            performKeyPairEncodingTest(keyPair);
            assertEquals(oids[i], SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
        }
    }

}
