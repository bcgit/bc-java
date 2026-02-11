package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.SM2KeyExchangeSpec;
import org.bouncycastle.util.Arrays;


public class GMKeyExchangeSpi
    extends BaseAgreementSpi
{
    private final String kaAlgorithm;
    private final SM2KeyExchange engine;
    private SM2KeyExchangeSpec  spec;
    private byte[] result;

    protected GMKeyExchangeSpi(String kaAlgorithm)
    {
        super(kaAlgorithm, null);

        this.kaAlgorithm = kaAlgorithm;
        this.engine = new SM2KeyExchange();
    }

    protected Key engineDoPhase(
        Key key,
        boolean lastPhase)
        throws InvalidKeyException, IllegalStateException
    {
        if (spec == null)
        {
            throw new IllegalStateException(kaAlgorithm + " not initialised.");
        }

        if (!lastPhase)
        {
            throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
        }

        if (!(key instanceof BCECPublicKey))
        {
            throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                + getSimpleName(BCECPublicKey.class) + " for doPhase");
        }
        ECPublicKeyParameters staticKey = (ECPublicKeyParameters)ECUtils.generatePublicKeyParameter((PublicKey)key);
        ECPublicKeyParameters ephemeralKey = (ECPublicKeyParameters)ECUtils.generatePublicKeyParameter(spec.getOtherPartyEphemeralKey());

        ParametersWithID parameters = new ParametersWithID(new SM2KeyExchangePublicParameters(staticKey, ephemeralKey),
            spec.getOtherPartyId());

        result = engine.calculateKey(128, parameters);

        return null;
    }

    protected void doInitFromKey(Key key, AlgorithmParameterSpec parameterSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (parameterSpec != null && !(parameterSpec instanceof SM2KeyExchangeSpec))
        {
            throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
        }

        if (!(key instanceof PrivateKey))
        {
            throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                + getSimpleName(BCECPrivateKey.class) + " for initialisation");
        }
        spec = (SM2KeyExchangeSpec)parameterSpec;

        ECPrivateKeyParameters staticKey = (ECPrivateKeyParameters)ECUtils.generatePrivateKeyParameter((PrivateKey)key);
        ECPrivateKeyParameters ephemeralKey = (ECPrivateKeyParameters)ECUtils.generatePrivateKeyParameter(spec.getEphemeralPrivateKey());
        ParametersWithID parameters = new ParametersWithID(new SM2KeyExchangePrivateParameters(spec.isInitiator(), staticKey, ephemeralKey), spec.getId());
        engine.init(parameters);
    }

    private static String getSimpleName(Class clazz)
    {
        String fullName = clazz.getName();

        return fullName.substring(fullName.lastIndexOf('.') + 1);
    }

    protected byte[] doCalcSecret()
    {
        return Arrays.clone(result);
    }

    public static class SM2
        extends GMKeyExchangeSpi
    {
        public SM2()
        {
            super("SM2");
        }
    }
}
