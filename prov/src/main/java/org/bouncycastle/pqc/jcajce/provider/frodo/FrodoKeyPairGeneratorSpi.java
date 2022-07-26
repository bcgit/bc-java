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
import org.bouncycastle.util.Strings;

public class FrodoKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("frodokem19888r3", FrodoParameters.frodokem640aes);
        parameters.put("frodokem19888shaker3", FrodoParameters.frodokem640shake);
        parameters.put("frodokem31296r3", FrodoParameters.frodokem976aes);
        parameters.put("frodokem31296shaker3", FrodoParameters.frodokem976shake);
        parameters.put("frodokem43088r3", FrodoParameters.frodokem1344aes);
        parameters.put("frodokem43088shaker3", FrodoParameters.frodokem1344shake);
        parameters.put(FrodoParameterSpec.frodokem640aes.getName(), FrodoParameters.frodokem640aes);
        parameters.put(FrodoParameterSpec.frodokem640shake.getName(), FrodoParameters.frodokem640shake);
        parameters.put(FrodoParameterSpec.frodokem976aes.getName(), FrodoParameters.frodokem976aes);
        parameters.put(FrodoParameterSpec.frodokem976shake.getName(), FrodoParameters.frodokem976shake);
        parameters.put(FrodoParameterSpec.frodokem1344aes.getName(), FrodoParameters.frodokem1344aes);
        parameters.put(FrodoParameterSpec.frodokem1344shake.getName(), FrodoParameters.frodokem1344shake);
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
        String name = getNameFromParams(params);

        if (name != null)
        {
            param = new FrodoKeyGenerationParameters(random, (FrodoParameters)parameters.get(name));

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
        if (paramSpec instanceof FrodoParameterSpec)
        {
            FrodoParameterSpec frodoParams = (FrodoParameterSpec)paramSpec;
            return frodoParams.getName();
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
            param = new FrodoKeyGenerationParameters(random, FrodoParameters.frodokem1344shake);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        FrodoPublicKeyParameters pub = (FrodoPublicKeyParameters)pair.getPublic();
        FrodoPrivateKeyParameters priv = (FrodoPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCFrodoPublicKey(pub), new BCFrodoPrivateKey(priv));
    }
}
