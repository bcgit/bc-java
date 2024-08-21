package org.bouncycastle.pqc.jcajce.provider.test;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

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
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testKeyFactory()
            throws Exception
    {
        kf = KeyFactory.getInstance("ML-KEM", "BC");
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
        }
    }

}
