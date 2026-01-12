package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;


import org.bouncycastle.jcajce.provider.asymmetric.ec.BCSM2KeyExchangePrivateKey;
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

        keyAgreement.init(new BCSM2KeyExchangePrivateKey(kp1.getPrivate(), kp1.getPrivate(), Strings.toByteArray("ALICE123@YAHOO.COM")));
        //TODO: wrong parameters
        keyAgreement.doPhase(kp2.getPublic(), true);

        byte[] sec1 = keyAgreement.generateSecret();

        keyAgreement.init(kp2.getPrivate());

        keyAgreement.doPhase(kp1.getPublic(), true);

        byte[] sec2 = keyAgreement.generateSecret();

        isTrue(areEqual(sec1, sec2));
        byte[] id = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(id);
        AlgorithmParameterSpec spec = new SM2ParameterSpec(id);
        if (spec != null)
        {
            keyAgreement.init(kp1.getPrivate(), spec);

            keyAgreement.doPhase(kp2.getPublic(), true);

            byte[] sec3 = keyAgreement.generateSecret();

            keyAgreement.init(kp2.getPrivate(), spec);

            keyAgreement.doPhase(kp1.getPublic(), true);

            byte[] sec4 = keyAgreement.generateSecret();

            isTrue(areEqual(sec3, sec4));
            isTrue(!areEqual(sec1, sec4));
        }
    }
}
