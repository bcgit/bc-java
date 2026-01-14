package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jcajce.spec.SM2KeyExchangeSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class SM2KeyExchangeTest
    extends SimpleTest
{
    public static void main(String[] args)
        throws Exception
    {
        SM2KeyExchangeTest test = new SM2KeyExchangeTest();
        Security.addProvider(new BouncyCastleProvider());
        test.performTest();
    }

    @Override
    public String getName()
    {
        return "SM2KeyExchange";
    }

    @Override
    public void performTest()
        throws Exception
    {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", "BC");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM2", "BC");
        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();
        KeyPair kp3 = kpGen.generateKeyPair();
        KeyPair kp4 = kpGen.generateKeyPair();

        keyAgreement.init(kp1.getPrivate(), new SM2KeyExchangeSpec(true, kp2.getPrivate(), kp4.getPublic(), Strings.toByteArray("ALICE123@YAHOO.COM"), Strings.toByteArray("BILL456@YAHOO.COM")));
        keyAgreement.doPhase(kp3.getPublic(), true);

        byte[] sec1 = keyAgreement.generateSecret();

        keyAgreement.init(kp3.getPrivate(), new SM2KeyExchangeSpec(false, kp4.getPrivate(), kp2.getPublic(), Strings.toByteArray("BILL456@YAHOO.COM"), Strings.toByteArray("ALICE123@YAHOO.COM")));

        keyAgreement.doPhase(kp1.getPublic(), true);

        byte[] sec2 = keyAgreement.generateSecret();

        isTrue(areEqual(sec1, sec2));
        byte[] id1 = new byte[16];
        byte[] id2 = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(id1);
        random.nextBytes(id2);

        keyAgreement.init(kp1.getPrivate(), new SM2KeyExchangeSpec(true, kp2.getPrivate(), kp4.getPublic(), id1, id2));
        keyAgreement.doPhase(kp3.getPublic(), true);

        byte[] sec3 = keyAgreement.generateSecret();

        keyAgreement.init(kp3.getPrivate(), new SM2KeyExchangeSpec(false, kp4.getPrivate(), kp2.getPublic(), id2, id1));

        keyAgreement.doPhase(kp1.getPublic(), true);

        byte[] sec4 = keyAgreement.generateSecret();

        isTrue(areEqual(sec3, sec4));
        isTrue(!areEqual(sec1, sec4));

    }
}
