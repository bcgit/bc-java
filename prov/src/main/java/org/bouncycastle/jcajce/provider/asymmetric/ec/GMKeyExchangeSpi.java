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
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.util.Arrays;

/**
 * Diffie-Hellman key agreement using elliptic curve keys, ala IEEE P1363
 * both the simple one, and the simple one with cofactors are supported.
 * <p>
 * Also, MQV key agreement per SEC-1
 */
public class GMKeyExchangeSpi
    extends BaseAgreementSpi
{
    private static final X9IntegerConverter converter = new X9IntegerConverter();

    private String kaAlgorithm;

    private ParametersWithID parameters;
    private Object agreement;

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

        if (!(key instanceof BCSM2KeyExchangePublicKey))
        {
            throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                + getSimpleName(BCSM2KeyExchangePublicKey.class) + " for doPhase");
        }
        BCSM2KeyExchangePublicKey k = (BCSM2KeyExchangePublicKey)key;
        ECPublicKeyParameters staticPubKey = (ECPublicKeyParameters)ECUtils.generatePublicKeyParameter(k.getStaticPublicKey());
        ECPublicKeyParameters ephemeralPubKey = (ECPublicKeyParameters)ECUtils.generatePublicKeyParameter(k.getEphemeralPublicKey());

        ParametersWithID parameters = new ParametersWithID(new SM2KeyExchangePublicParameters(staticPubKey, ephemeralPubKey), k.getId());

        result = bigIntToBytes(((BasicAgreement)agreement).calculateAgreement(parameters), (BCECPublicKey)k.getStaticPublicKey());

        return null;
    }

    protected void doInitFromKey(Key key, AlgorithmParameterSpec parameterSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (parameterSpec != null && !(parameterSpec instanceof SM2ParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
        }

        if (!(key instanceof PrivateKey))
        {
            throw new InvalidKeyException(kaAlgorithm + " key agreement requires "
                + getSimpleName(ECPrivateKey.class) + " for initialisation");
        }

        byte[] id = ((SM2ParameterSpec)parameterSpec).getID();

        ECPrivateKeyParameters staticKey = (ECPrivateKeyParameters)ECUtils.generatePrivateKeyParameter(((BCSM2KeyExchangePrivateKey)key).getStaticPrivateKey());
        ECPrivateKeyParameters ephemeralKey = (ECPrivateKeyParameters)ECUtils.generatePrivateKeyParameter(((BCSM2KeyExchangePrivateKey)key).getEphemeralPrivateKey());
        this.parameters = new ParametersWithID(new SM2KeyExchangePrivateParameters(((BCSM2KeyExchangePrivateKey)key).isInitiator(), staticKey, ephemeralKey), id);
        ((BasicAgreement)agreement).init(parameters);
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

    public static class SM2KeyAgreement
        implements BasicAgreement
    {
        private final SM2KeyExchange engine;

        public SM2KeyAgreement()
        {
            engine = new SM2KeyExchange();
        }

        @Override
        public void init(CipherParameters param)
        {
            engine.init(param);
        }

        @Override
        public int getFieldSize()
        {
            return 0;
        }

        @Override
        public BigInteger calculateAgreement(CipherParameters pubKey)
        {
            byte[] rlt = engine.calculateKey(128, pubKey);
            return new BigInteger(1, rlt);
        }
    }
}
