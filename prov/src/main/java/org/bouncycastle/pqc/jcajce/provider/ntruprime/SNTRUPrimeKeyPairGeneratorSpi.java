package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.util.Strings;

public class SNTRUPrimeKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(SNTRUPrimeParameterSpec.sntrup653.getName(), SNTRUPrimeParameters.sntrup653);
        parameters.put(SNTRUPrimeParameterSpec.sntrup761.getName(), SNTRUPrimeParameters.sntrup761);
        parameters.put(SNTRUPrimeParameterSpec.sntrup857.getName(), SNTRUPrimeParameters.sntrup857);
        parameters.put(SNTRUPrimeParameterSpec.sntrup953.getName(), SNTRUPrimeParameters.sntrup953);
        parameters.put(SNTRUPrimeParameterSpec.sntrup1013.getName(), SNTRUPrimeParameters.sntrup1013);
        parameters.put(SNTRUPrimeParameterSpec.sntrup1277.getName(), SNTRUPrimeParameters.sntrup1277);
    }

    SNTRUPrimeKeyGenerationParameters param;
    SNTRUPrimeKeyPairGenerator engine = new SNTRUPrimeKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SNTRUPrimeKeyPairGeneratorSpi()
    {
        super("SNTRUPrime");
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
            param = new SNTRUPrimeKeyGenerationParameters(random, (SNTRUPrimeParameters)parameters.get(name));

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
        if (paramSpec instanceof SNTRUPrimeParameterSpec)
        {
            SNTRUPrimeParameterSpec frodoParams = (SNTRUPrimeParameterSpec)paramSpec;
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
            param = new SNTRUPrimeKeyGenerationParameters(random, SNTRUPrimeParameters.sntrup953);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SNTRUPrimePublicKeyParameters pub = (SNTRUPrimePublicKeyParameters)pair.getPublic();
        SNTRUPrimePrivateKeyParameters priv = (SNTRUPrimePrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSNTRUPrimePublicKey(pub), new BCSNTRUPrimePrivateKey(priv));
    }
}
