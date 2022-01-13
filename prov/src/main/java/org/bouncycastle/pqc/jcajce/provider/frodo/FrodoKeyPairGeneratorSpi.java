package org.bouncycastle.pqc.jcajce.provider.frodo;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

public class FrodoKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(FrodoParameterSpec.frodokem19888r3.getName(), FrodoParameters.frodokem19888r3);
        parameters.put(FrodoParameterSpec.frodokem19888shaker3.getName(), FrodoParameters.frodokem19888shaker3);
        parameters.put(FrodoParameterSpec.frodokem31296r3.getName(), FrodoParameters.frodokem31296r3);
        parameters.put(FrodoParameterSpec.frodokem31296shaker3.getName(), FrodoParameters.frodokem31296shaker3);
        parameters.put(FrodoParameterSpec.frodokem43088r3.getName(), FrodoParameters.frodokem43088r3);
        parameters.put(FrodoParameterSpec.frodokem43088shaker3.getName(), FrodoParameters.frodokem43088shaker3);
    }

    FrodoKeyGenerationParameters param;
    FrodoKeyPairGenerator engine = new FrodoKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public FrodoKeyPairGeneratorSpi()
    {
        super("Frodo");
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
        if (!(params instanceof FrodoParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a FrodoParameterSpec");
        }

        param = new FrodoKeyGenerationParameters(random, (FrodoParameters)parameters.get(getNameFromParams(params)));

        engine.init(param);
        initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
            throws InvalidAlgorithmParameterException
    {
        if (paramSpec instanceof FrodoParameterSpec)
        {
            FrodoParameterSpec frodoParams = (FrodoParameterSpec)paramSpec;
            return frodoParams.getName();
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
            param = new FrodoKeyGenerationParameters(random, FrodoParameters.frodokem43088shaker3);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        FrodoPublicKeyParameters pub = (FrodoPublicKeyParameters)pair.getPublic();
        FrodoPrivateKeyParameters priv = (FrodoPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCFrodoPublicKey(pub), new BCFrodoPrivateKey(priv));
    }
}
