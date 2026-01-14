package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.SM2KeyExchangeSpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.util.Arrays;


public class GMKeyExchangeSpi
    extends BaseAgreementSpi
{
    private static final X9IntegerConverter converter = new X9IntegerConverter();

    private final String kaAlgorithm;
    private ParametersWithID parameters;
    private final BasicAgreement agreement;
    private SM2KeyExchangeSpec  spec;
    private byte[] result;

    protected GMKeyExchangeSpi(
        String kaAlgorithm,
        BasicAgreement agreement,
        DerivationFunction kdf)
    {
        super(kaAlgorithm, kdf);

        this.kaAlgorithm = kaAlgorithm;
        this.agreement = agreement;
    }

    protected byte[] bigIntToBytes(
        BigInteger r, BCECPublicKey key)
    {
        return converter.integerToBytes(r, converter.getByteLength(key.engineGetSpec().getCurve()));
    }

    protected Key engineDoPhase(
        Key key,
        boolean lastPhase)
        throws InvalidKeyException, IllegalStateException
    {
        if (parameters == null)
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
        BCECPublicKey k = (BCECPublicKey)key;
        ECPublicKeyParameters staticKey = (ECPublicKeyParameters)
            ECUtils.generatePublicKeyParameter((PublicKey)key);
        ECPublicKeyParameters ephemKey = (ECPublicKeyParameters)
            ECUtils.generatePublicKeyParameter(spec.getOtherPartyEphemeralKey());

        ParametersWithID parameters = new ParametersWithID(new SM2KeyExchangePublicParameters(staticKey, ephemKey),
            spec.getOtherPartyId());

        result = bigIntToBytes(agreement.calculateAgreement(parameters), k);

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
                + getSimpleName(ECPrivateKey.class) + " for initialisation");
        }
        spec = (SM2KeyExchangeSpec)parameterSpec;
        byte[] id = spec.getId();

        ECPrivateKeyParameters staticKey = (ECPrivateKeyParameters)ECUtils.generatePrivateKeyParameter((PrivateKey)key);
        ECPrivateKeyParameters ephemeralKey = (ECPrivateKeyParameters)ECUtils.generatePrivateKeyParameter(spec.getEphemeralPrivateKey());
        this.parameters = new ParametersWithID(new SM2KeyExchangePrivateParameters(spec.isInitiator(), staticKey, ephemeralKey), id);
        agreement.init(parameters);
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
            super("SM2", new SM2KeyAgreement(), null);
        }
    }

    private static class SM2KeyAgreement
        implements BasicAgreement
    {
        private final SM2KeyExchange engine;
        private int fieldSize;
        public SM2KeyAgreement()
        {
            engine = new SM2KeyExchange();
        }

        @Override
        public void init(CipherParameters param)
        {
            engine.init(param);
            fieldSize = ((SM2KeyExchangePrivateParameters)((ParametersWithID)param).getParameters()).getStaticPrivateKey()
                .getParameters().getCurve().getFieldElementEncodingLength();
        }

        @Override
        public int getFieldSize()
        {
            return fieldSize;
        }

        @Override
        public BigInteger calculateAgreement(CipherParameters pubKey)
        {
            byte[] rlt = engine.calculateKey(128, pubKey);
            return new BigInteger(1, rlt);
        }
    }
}
