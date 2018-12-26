package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.interfaces.NHKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

/**
 * Test cases for the use of NewHope (NH) with the BCPQC provider.
 */
public class NewHopeTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testKeyExchange()
        throws Exception
    {
        SecureRandom aliceRand = new SecureRandom();
        SecureRandom bobRand = new SecureRandom();

        for (int i = 0; i < 1000; ++i)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("NH", "BCPQC");

            kpGen.initialize(1024, aliceRand);

            KeyPair aliceKp = kpGen.generateKeyPair();

            KeyAgreement bobAgree = KeyAgreement.getInstance("NH", "BCPQC");

            // responder has no private key, but needs a random number source.
            bobAgree.init(null, bobRand);

            Key bobSend = bobAgree.doPhase(aliceKp.getPublic(), true);

            KeyAgreement aliceAgree = KeyAgreement.getInstance("NH", "BCPQC");

            // initiator uses both private key
            aliceAgree.init(aliceKp.getPrivate());

            // and recipient's public key.
            aliceAgree.doPhase(bobSend, true);

            assertTrue("value mismatch", Arrays.areEqual(aliceAgree.generateSecret(), bobAgree.generateSecret()));
        }
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NH", "BCPQC");

        kpg.initialize(1024, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("NH", "BCPQC");

        NHKey privKey = (NHKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        NHKey privKey2 = (NHKey)oIn.readObject();

        assertEquals(privKey, privKey2);
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NH", "BCPQC");

        kpg.initialize(1024, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("NH", "BCPQC");

        NHKey pubKey = (NHKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        NHKey pubKey2 = (NHKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
    }
}
