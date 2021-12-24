package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;


public class McElieceKeyPairGeneratorTest
    extends KeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("McEliece");
        kf = KeyFactory.getInstance(PQCObjectIdentifiers.mcEliece.getId());
    }

    public void testKeyPairEncoding_9_33()
        throws Exception
    {
        kf = KeyFactory.getInstance("McEliece");

        kpg = KeyPairGenerator.getInstance("McEliece");
        McElieceKeyGenParameterSpec params = new McElieceKeyGenParameterSpec(9, 33);
        kpg.initialize(params);
        simpleKeyPairEncodingTest(kpg.generateKeyPair());

        kpg = KeyPairGenerator.getInstance("McEliece");
        kpg.initialize(params, new SecureRandom());
        simpleKeyPairEncodingTest(kpg.generateKeyPair());
    }

    private void simpleKeyPairEncodingTest(KeyPair keyPair)
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

    public void testKeyPairEncoding_CCA2()
        throws Exception
    {
        kf = KeyFactory.getInstance("McEliece-CCA2");

        kpg = KeyPairGenerator.getInstance("McEliece-CCA2");
        McElieceCCA2KeyGenParameterSpec params = new McElieceCCA2KeyGenParameterSpec(9, 33);
        kpg.initialize(params);
        performKeyPairEncodingTest(kpg.generateKeyPair());

        kpg = KeyPairGenerator.getInstance("McEliece-CCA2");
        kpg.initialize(params, new SecureRandom());
        performKeyPairEncodingTest(kpg.generateKeyPair());
    }
}
