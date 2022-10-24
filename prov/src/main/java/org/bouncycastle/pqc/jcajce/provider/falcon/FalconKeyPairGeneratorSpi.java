package org.bouncycastle.pqc.jcajce.provider.falcon;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.util.Strings;

public class FalconKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(FalconParameterSpec.falcon_512.getName(), FalconParameters.falcon_512);
        parameters.put(FalconParameterSpec.falcon_1024.getName(), FalconParameters.falcon_1024);
    }

    private final FalconParameters falconParameters;

    FalconKeyGenerationParameters param;
    FalconKeyPairGenerator engine = new FalconKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public FalconKeyPairGeneratorSpi()
    {
        super("FALCON");
        this.falconParameters = null;
    }

    protected FalconKeyPairGeneratorSpi(FalconParameters falconParameters)
    {
        super(falconParameters.getName());
        this.falconParameters = falconParameters;
    }

    public void initialize(
            int strength,
            SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);

        if (name != null && parameters.containsKey(name))
        {
            FalconParameters falconParams = (FalconParameters)parameters.get(name);

            param = new FalconKeyGenerationParameters(random, falconParams);

            if (falconParameters != null && !falconParams.getName().equals(falconParameters.getName()))
            {
                 throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(falconParameters.getName()));
            }

            engine.init(param);
            initialised = true;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof FalconParameterSpec)
        {
            FalconParameterSpec falconParams = (FalconParameterSpec)paramSpec;
            return falconParams.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            if (falconParameters != null)
            {
                param = new FalconKeyGenerationParameters(random, falconParameters);
            }
            else
            {
                param = new FalconKeyGenerationParameters(random, FalconParameters.falcon_512);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        FalconPublicKeyParameters pub = (FalconPublicKeyParameters)pair.getPublic();
        FalconPrivateKeyParameters priv = (FalconPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCFalconPublicKey(pub), new BCFalconPrivateKey(priv));
    }

    public static class Falcon512
        extends FalconKeyPairGeneratorSpi
    {
        public Falcon512()
        {
            super(FalconParameters.falcon_512);
        }
    }

    public static class Falcon1024
        extends FalconKeyPairGeneratorSpi
    {
        public Falcon1024()
        {
            super(FalconParameters.falcon_1024);
        }
    }
}
