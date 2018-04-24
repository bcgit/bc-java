package org.bouncycastle.pqc.jcajce.provider.newhope;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.pqc.crypto.newhope.NHAgreement;
import org.bouncycastle.pqc.crypto.newhope.NHExchangePairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.util.Arrays;

public class KeyAgreementSpi
    extends BaseAgreementSpi
{
    private NHAgreement agreement;
    private BCNHPublicKey otherPartyKey;
    private NHExchangePairGenerator exchangePairGenerator;

    private byte[] shared;

    public KeyAgreementSpi()
    {
        super("NH", null);
    }

    protected void engineInit(Key key, SecureRandom secureRandom)
        throws InvalidKeyException
    {
        if (key != null)
        {
            agreement = new NHAgreement();

            agreement.init(((BCNHPrivateKey)key).getKeyParams());
        }
        else
        {
            exchangePairGenerator = new NHExchangePairGenerator(secureRandom);
        }
    }

    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("NewHope does not require parameters");
    }

    protected Key engineDoPhase(Key key, boolean lastPhase)
        throws InvalidKeyException, IllegalStateException
    {
        if (!lastPhase)
        {
            throw new IllegalStateException("NewHope can only be between two parties.");
        }

        otherPartyKey = (BCNHPublicKey)key;

        if (exchangePairGenerator != null)
        {
            ExchangePair exchPair = exchangePairGenerator.generateExchange((AsymmetricKeyParameter)otherPartyKey.getKeyParams());

            shared = exchPair.getSharedValue();

            return new BCNHPublicKey((NHPublicKeyParameters)exchPair.getPublicKey());
        }
        else
        {
            shared = agreement.calculateAgreement(otherPartyKey.getKeyParams());

            return null;
        }
    }

    protected byte[] engineGenerateSecret()
        throws IllegalStateException
    {
        byte[] rv = Arrays.clone(shared);

        Arrays.fill(shared, (byte)0);

        return rv;
    }

    protected int engineGenerateSecret(byte[] bytes, int offset)
        throws IllegalStateException, ShortBufferException
    {
        System.arraycopy(shared, 0, bytes, offset, shared.length);

        Arrays.fill(shared, (byte)0);

        return shared.length;
    }

    protected byte[] calcSecret()
    {
        return engineGenerateSecret();
    }
}
