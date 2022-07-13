package org.bouncycastle.pqc.jcajce.provider.falcon;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
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
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public class FalconKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(FalconParameterSpec.falcon_512.getName(), FalconParameters.falcon_512);
        parameters.put(FalconParameterSpec.falcon_1024.getName(), FalconParameters.falcon_1024);
    }

    FalconKeyGenerationParameters param;
    FalconKeyPairGenerator engine = new FalconKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public FalconKeyPairGeneratorSpi()
    {
        super("Falcon");
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
        if (!(params instanceof FalconParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a FalconParameterSpec");
        }

        param = new FalconKeyGenerationParameters(random, (FalconParameters)parameters.get(getNameFromParams(params)));

        engine.init(param);
        
        initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
            throws InvalidAlgorithmParameterException
    {
        if (paramSpec instanceof FalconParameterSpec)
        {
            FalconParameterSpec falonParams = (FalconParameterSpec)paramSpec;
            return falonParams.getName();
        }
        else
        {
            return SpecUtil.getNameFrom(paramSpec);
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new FalconKeyGenerationParameters(random, FalconParameters.falcon_512);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        FalconPublicKeyParameters pub = (FalconPublicKeyParameters)pair.getPublic();
        FalconPrivateKeyParameters priv = (FalconPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCFalconPublicKey(pub), new BCFalconPrivateKey(priv));
    }
}
