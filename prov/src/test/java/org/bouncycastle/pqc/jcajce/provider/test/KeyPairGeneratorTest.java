package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public abstract class KeyPairGeneratorTest
    extends FlexiTest
{

    protected KeyPairGenerator kpg;

    protected KeyFactory kf;

    protected final void performKeyPairEncodingTest(KeyPair keyPair)
    {
        try
        {
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey privKey = keyPair.getPrivate();

            byte[] encPubKey = pubKey.getEncoded();
            byte[] encPrivKey = privKey.getEncoded();

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encPubKey);
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encPrivKey);

            PublicKey decPubKey = kf.generatePublic(pubKeySpec);
            PrivateKey decPrivKey = kf.generatePrivate(privKeySpec);

            assertEquals(pubKey, decPubKey);
            assertEquals(privKey, decPrivKey);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail(e);
        }
    }

}
