package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCSM2KeyExchangePrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCSM2KeyExchangePublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
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

        keyAgreement.init(new BCSM2KeyExchangePrivateKey(true, kp1.getPrivate(), kp2.getPrivate()), new SM2ParameterSpec(Strings.toByteArray("ALICE123@YAHOO.COM")));
        keyAgreement.doPhase(new BCSM2KeyExchangePublicKey(kp3.getPublic(), kp4.getPublic(), Strings.toByteArray("BILL456@YAHOO.COM")), true);

        byte[] sec1 = keyAgreement.generateSecret();

        keyAgreement.init(new BCSM2KeyExchangePrivateKey(false, kp3.getPrivate(), kp4.getPrivate()), new SM2ParameterSpec(Strings.toByteArray("BILL456@YAHOO.COM")));

        keyAgreement.doPhase(new BCSM2KeyExchangePublicKey(kp1.getPublic(), kp2.getPublic(), Strings.toByteArray("ALICE123@YAHOO.COM")), true);

        byte[] sec2 = keyAgreement.generateSecret();

        isTrue(areEqual(sec1, sec2));
        byte[] id1 = new byte[16];
        byte[] id2 = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(id1);
        random.nextBytes(id2);
        AlgorithmParameterSpec spec1 = new SM2ParameterSpec(id1);
        AlgorithmParameterSpec spec2 = new SM2ParameterSpec(id2);

        keyAgreement.init(new BCSM2KeyExchangePrivateKey(true, kp1.getPrivate(), kp2.getPrivate()),spec1);

        keyAgreement.doPhase(new BCSM2KeyExchangePublicKey(kp3.getPublic(), kp4.getPublic(), id2), true);

        byte[] sec3 = keyAgreement.generateSecret();

        keyAgreement.init(new BCSM2KeyExchangePrivateKey(false, kp3.getPrivate(), kp4.getPrivate()), spec2);

        keyAgreement.doPhase(new BCSM2KeyExchangePublicKey(kp1.getPublic(), kp2.getPublic(), id1), true);

        byte[] sec4 = keyAgreement.generateSecret();

        isTrue(areEqual(sec3, sec4));
        isTrue(!areEqual(sec1, sec4));

    }
}
