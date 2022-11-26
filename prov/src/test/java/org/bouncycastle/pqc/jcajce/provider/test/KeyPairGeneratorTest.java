package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
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
        performKeyPairEncodingTest(null, keyPair);
    }

    protected final void performKeyPairEncodingTest(String name, KeyPair keyPair)
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
            assertEquals(pubKey.getAlgorithm(), decPubKey.getAlgorithm());
            assertEquals(pubKey.hashCode(), decPubKey.hashCode());

            assertEquals(privKey, decPrivKey);
            assertEquals(privKey.getAlgorithm(), decPrivKey.getAlgorithm());
            assertEquals(privKey.hashCode(), decPrivKey.hashCode());

            if (name != null)
            {
                KeyFactory nkf = KeyFactory.getInstance(name, "BCPQC");

                decPubKey = nkf.generatePublic(pubKeySpec);
                decPrivKey = nkf.generatePrivate(privKeySpec);

                assertEquals(pubKey, decPubKey);
                assertEquals(pubKey.getAlgorithm(), decPubKey.getAlgorithm());
                assertEquals(pubKey.hashCode(), decPubKey.hashCode());

                assertEquals(privKey, decPrivKey);
                assertEquals(privKey.getAlgorithm(), decPrivKey.getAlgorithm());
                assertEquals(privKey.hashCode(), decPrivKey.hashCode());
            }
            checkSerialisation(pubKey);
            checkSerialisation(privKey);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail(e);
        }
    }

    private void checkSerialisation(Key key)
        throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(key);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        Key inKey = (Key)oIn.readObject();

        assertEquals(key, inKey);
        assertEquals(key.getAlgorithm(), inKey.getAlgorithm());
        assertEquals(key.hashCode(), inKey.hashCode());
    }

}
