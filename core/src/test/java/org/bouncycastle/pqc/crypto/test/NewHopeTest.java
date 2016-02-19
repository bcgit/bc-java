package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.pqc.crypto.newhope.NHAgreement;
import org.bouncycastle.pqc.crypto.newhope.NHExchangePairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class NewHopeTest
    extends SimpleTest
{
    private void testKeyExchange()
        throws Exception
    {
        SecureRandom aliceRand = new SecureRandom();
        SecureRandom bobRand = new SecureRandom();

        for (int i = 0; i < 1000; ++i)
        {
            NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

            kpGen.init(new KeyGenerationParameters(aliceRand, 2048));

            AsymmetricCipherKeyPair aliceKp = kpGen.generateKeyPair();

            NHExchangePairGenerator exchGen = new NHExchangePairGenerator(bobRand);

            ExchangePair bobExchPair = exchGen.GenerateExchange(aliceKp.getPublic());

            NHAgreement agreement = new NHAgreement();

            agreement.init(aliceKp.getPrivate());

            byte[] aliceSharedKey = agreement.calculateAgreement(bobExchPair.getPublicKey());

            isTrue("value mismatch", Arrays.areEqual(aliceSharedKey, bobExchPair.getSharedValue()));
        }
    }

    public String getName()
    {
        return "NewHope";
    }

    public void performTest()
        throws Exception
    {
        testKeyExchange();
    }

    public static void main(
            String[]    args)
    {
        runTest(new NewHopeTest());
    }
}
