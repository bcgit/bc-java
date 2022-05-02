package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * KeyFactory/KeyPairGenerator tests for Picnic with the BCPQC provider.
 */
public class PicnicKeyPairGeneratorTest
        extends KeyPairGeneratorTest
{
    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
            throws Exception
    {
        kf = KeyFactory.getInstance("Picnic", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_mceliece.getId(), "BCPQC");
    }

    public void testKeySpecs()
            throws Exception
    {
        kf = KeyFactory.getInstance("Picnic", "BCPQC");
        kpg = KeyPairGenerator.getInstance("Picnic", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        PKCS8EncodedKeySpec privSpec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);

        assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), privSpec.getEncoded()));

        X509EncodedKeySpec pubSpec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);

        assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pubSpec.getEncoded()));
    }

    public void testKeyPairEncoding()
            throws Exception
    {
        PicnicParameterSpec[] specs =
                new PicnicParameterSpec[]
                        {
                            PicnicParameterSpec.picnicl1fs,
                            PicnicParameterSpec.picnicl1ur,
                            PicnicParameterSpec.picnicl3fs,
                            PicnicParameterSpec.picnicl3ur,
                            PicnicParameterSpec.picnicl5fs,
                            PicnicParameterSpec.picnicl5ur,
                            PicnicParameterSpec.picnic3l1,
                            PicnicParameterSpec.picnic3l3,
                            PicnicParameterSpec.picnic3l5,
                            PicnicParameterSpec.picnicl1full,
                            PicnicParameterSpec.picnicl3full,
                            PicnicParameterSpec.picnicl5full
                        };

        kf = KeyFactory.getInstance("Picnic", "BCPQC");

        kpg = KeyPairGenerator.getInstance("Picnic", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncodingTest(kpg.generateKeyPair());
        }
    }
}
