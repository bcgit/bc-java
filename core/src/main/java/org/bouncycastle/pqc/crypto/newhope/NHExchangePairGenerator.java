package org.bouncycastle.pqc.crypto.newhope;

import java.security.SecureRandom;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.pqc.crypto.ExchangePairGenerator;

public class NHExchangePairGenerator
    implements ExchangePairGenerator
{
    private final SecureRandom random;

    public NHExchangePairGenerator(SecureRandom random)
    {
        this.random = random;
    }

    public ExchangePair GenerateExchange(AsymmetricKeyParameter senderPublicKey)
    {
        NHPublicKeyParameters pubKey = (NHPublicKeyParameters)senderPublicKey;

        byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];
        byte[] publicKeyValue = new byte[NewHope.SEND_SIZE];

        NewHope.sharedB(random, sharedValue, publicKeyValue, pubKey.pubData);

        byte[] aliceReceived = publicKeyValue;

        return new ExchangePair(new NHPublicKeyParameters(publicKeyValue), sharedValue);
    }
}
