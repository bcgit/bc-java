package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * KeyFactory/KeyPairGenerator tests for CMCE with the BCPQC provider.
 */
public class CMCEKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("CMCE", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_mceliece.getId(), "BCPQC");
    }

    public void testKeySpecs()
        throws Exception
    {
        kf = KeyFactory.getInstance("CMCE", "BCPQC");
        kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        PKCS8EncodedKeySpec privSpec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);

        assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), privSpec.getEncoded()));

        X509EncodedKeySpec pubSpec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);

        assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pubSpec.getEncoded()));
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        CMCEParameterSpec[] specs =
            new CMCEParameterSpec[]
                {
                    CMCEParameterSpec.mceliece348864,
                    CMCEParameterSpec.mceliece348864f,
                    CMCEParameterSpec.mceliece460896,
                    CMCEParameterSpec.mceliece460896f,
                    CMCEParameterSpec.mceliece6688128,
                    CMCEParameterSpec.mceliece6688128f,
                    CMCEParameterSpec.mceliece6960119,
                    CMCEParameterSpec.mceliece6960119f,
                    CMCEParameterSpec.mceliece8192128,
                    CMCEParameterSpec.mceliece8192128f
                };

        kf = KeyFactory.getInstance("CMCE", "BCPQC");

        kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
        
        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }
}
