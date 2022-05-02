package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.interfaces.PicnicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.bouncycastle.util.Strings;

public class PicnicTest
    extends TestCase
{
    byte[] msg = Strings.toByteArray("Hello World!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testPrivateKeyRecovery()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Picnic", "BCPQC");

        kpg.initialize(PicnicParameterSpec.picnic3l1, new PicnicTest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Picnic", "BCPQC");

        PicnicKey privKey = (PicnicKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        PicnicKey privKey2 = (PicnicKey)oIn.readObject();

        assertEquals(privKey, privKey2);
    }

    public void testPublicKeyRecovery()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Picnic", "BCPQC");

        kpg.initialize(PicnicParameterSpec.picnic3l1, new PicnicTest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Picnic", "BCPQC");

        PicnicKey pubKey = (PicnicKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        PicnicKey pubKey2 = (PicnicKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
    }

    public void testPicnicRandomSigSHAKE()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Picnic", "BCPQC");

        kpg.initialize(PicnicParameterSpec.picnic3l1, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Picnic", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("Picnic", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    private static class RiggedRandom
            extends SecureRandom
    {
        public void nextBytes(byte[] bytes)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)(i & 0xff);
            }
        }
    }

}
