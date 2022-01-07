package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;


/**
 * KeyFactory/KeyPairGenerator tests for SPHINCSPlus with the BCPQC provider.
 */
public class SphincsPlusKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.sphincsPlus.getId(), "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.sphincsPlus_shake_256.getId(), "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.sphincsPlus_sha_256.getId(), "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.sphincsPlus_sha_512.getId(), "BCPQC");
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        kf = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");

        SPHINCSPlusParameterSpec[] params =
            {
                SPHINCSPlusParameterSpec.sha256_128f,
                SPHINCSPlusParameterSpec.sha256_128s,
                SPHINCSPlusParameterSpec.sha256_192f,
                SPHINCSPlusParameterSpec.sha256_192s,
                SPHINCSPlusParameterSpec.sha256_256f,
                SPHINCSPlusParameterSpec.sha256_256s,
                SPHINCSPlusParameterSpec.sha256_128f_simple,
                SPHINCSPlusParameterSpec.sha256_128s_simple,
                SPHINCSPlusParameterSpec.sha256_192f_simple,
                SPHINCSPlusParameterSpec.sha256_192s_simple,
                SPHINCSPlusParameterSpec.sha256_256f_simple,
                SPHINCSPlusParameterSpec.sha256_256s_simple,
                SPHINCSPlusParameterSpec.shake256_128f,
                SPHINCSPlusParameterSpec.shake256_128s,
                SPHINCSPlusParameterSpec.shake256_192f,
                SPHINCSPlusParameterSpec.shake256_192s,
                SPHINCSPlusParameterSpec.shake256_256f,
                SPHINCSPlusParameterSpec.shake256_256s,
                SPHINCSPlusParameterSpec.shake256_128f_simple,
                SPHINCSPlusParameterSpec.shake256_128s_simple,
                SPHINCSPlusParameterSpec.shake256_192f_simple,
                SPHINCSPlusParameterSpec.shake256_192s_simple,
                SPHINCSPlusParameterSpec.shake256_256f_simple,
                SPHINCSPlusParameterSpec.shake256_256s_simple
            };

        // expected object identifiers
        ASN1ObjectIdentifier[] oids =
            {
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_512,
                BCObjectIdentifiers.sphincsPlus_sha_512,
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_256,
                BCObjectIdentifiers.sphincsPlus_sha_512,
                BCObjectIdentifiers.sphincsPlus_sha_512,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256,
                BCObjectIdentifiers.sphincsPlus_shake_256
            };
        
        kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        
        for (int i = 0; i != params.length; i++)
        {
            kpg.initialize(params[i], new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            performKeyPairEncodingTest(keyPair);
            assertEquals(oids[i], SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
        }
    }

}
