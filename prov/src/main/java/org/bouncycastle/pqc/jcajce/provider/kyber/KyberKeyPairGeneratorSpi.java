package org.bouncycastle.pqc.jcajce.provider.kyber;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Strings;

public class KyberKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(KyberParameterSpec.kyber512.getName(), KyberParameters.kyber512);
        parameters.put(KyberParameterSpec.kyber768.getName(), KyberParameters.kyber768);
        parameters.put(KyberParameterSpec.kyber1024.getName(), KyberParameters.kyber1024);
    }

    KyberKeyGenerationParameters param;
    KyberKeyPairGenerator engine = new KyberKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;
    private KyberParameters kyberParameters;

    public KyberKeyPairGeneratorSpi()
    {
        super("KYBER");
        this.kyberParameters = null;
    }

    protected KyberKeyPairGeneratorSpi(KyberParameters kyberParameters)
    {
        super(Strings.toUpperCase(kyberParameters.getName()));
        this.kyberParameters = kyberParameters;
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
            KyberParameters kyberParams = (KyberParameters)parameters.get(name);

            param = new KyberKeyGenerationParameters(random, kyberParams);

            if (kyberParameters != null && !kyberParams.getName().equals(kyberParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(kyberParameters.getName()));
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
        if (paramSpec instanceof KyberParameterSpec)
        {
            KyberParameterSpec kyberParams = (KyberParameterSpec)paramSpec;
            return kyberParams.getName();
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
            if (kyberParameters != null)
            {
                param = new KyberKeyGenerationParameters(random, kyberParameters);
            }
            else
            {
                param = new KyberKeyGenerationParameters(random, KyberParameters.kyber1024);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        KyberPublicKeyParameters pub = (KyberPublicKeyParameters)pair.getPublic();
        KyberPrivateKeyParameters priv = (KyberPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCKyberPublicKey(pub), new BCKyberPrivateKey(priv));
    }

    public static class Kyber512
        extends KyberKeyPairGeneratorSpi
    {
        public Kyber512()
        {
            super(KyberParameters.kyber512);
        }
    }

    public static class Kyber768
        extends KyberKeyPairGeneratorSpi
    {
        public Kyber768()
        {
            super(KyberParameters.kyber768);
        }
    }

    public static class Kyber1024
        extends KyberKeyPairGeneratorSpi
    {
        public Kyber1024()
        {
            super(KyberParameters.kyber1024);
        }
    }
}
