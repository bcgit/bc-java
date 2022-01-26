package org.bouncycastle.pqc.jcajce.provider.saber;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.saber.*;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SABERKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(SABERParameterSpec.lightsaberkemr3.getName(), SABERParameters.lightsaberkemr3);
        parameters.put(SABERParameterSpec.saberkemr3.getName(), SABERParameters.saberkemr3);
        parameters.put(SABERParameterSpec.firesaberkemr3.getName(), SABERParameters.firesaberkemr3);
    }

    SABERKeyGenerationParameters param;
    SABERKeyPairGenerator engine = new SABERKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SABERKeyPairGeneratorSpi()
    {
        super("SABER");
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
        if (!(params instanceof SABERParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a SABERParameterSpec");
        }

        param = new SABERKeyGenerationParameters(random, (SABERParameters)parameters.get(getNameFromParams(params)));

        engine.init(param);
        initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
        throws InvalidAlgorithmParameterException
    {
        if (paramSpec instanceof SABERParameterSpec)
        {
            SABERParameterSpec saberParams = (SABERParameterSpec)paramSpec;
            return saberParams.getName();
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
            param = new SABERKeyGenerationParameters(random, SABERParameters.firesaberkemr3);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SABERPublicKeyParameters pub = (SABERPublicKeyParameters)pair.getPublic();
        SABERPrivateKeyParameters priv = (SABERPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSABERPublicKey(pub), new BCSABERPrivateKey(priv));
    }
}