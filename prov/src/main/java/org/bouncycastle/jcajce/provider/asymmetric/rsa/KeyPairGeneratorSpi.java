package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static final AlgorithmIdentifier PKCS_ALGID = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final AlgorithmIdentifier PSS_ALGID = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS);

    final static BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);

    RSAKeyGenerationParameters param;
    RSAKeyPairGenerator engine;
    AlgorithmIdentifier algId;

    public KeyPairGeneratorSpi(
        String algorithmName,
        AlgorithmIdentifier algId)
    {
        super(algorithmName);

        this.algId = algId;
        engine = new RSAKeyPairGenerator();
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048));
        engine.init(param);
    }

    public KeyPairGeneratorSpi()
    {
        this("RSA", PKCS_ALGID);
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            random, strength, PrimeCertaintyCalculator.getDefaultCertainty(strength));

        engine.init(param);
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof RSAKeyGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
        }
        RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec)params;

        param = new RSAKeyGenerationParameters(
            rsaParams.getPublicExponent(),
            random, rsaParams.getKeysize(), PrimeCertaintyCalculator.getDefaultCertainty(2048));

        engine.init(param);
    }

    public KeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();

        return new KeyPair(new BCRSAPublicKey(algId, pub),
            new BCRSAPrivateCrtKey(algId, priv));
    }

    public static class PSS
        extends KeyPairGeneratorSpi
    {
        public PSS()
        {
            super("RSASSA-PSS", PSS_ALGID);
        }
    }
}
