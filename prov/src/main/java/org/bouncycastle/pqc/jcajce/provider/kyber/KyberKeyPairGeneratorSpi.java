package org.bouncycastle.pqc.jcajce.provider.kyber;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Strings;

public class KyberKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(KyberParameterSpec.kyber512.getName(), MLKEMParameters.ml_kem_512);
        parameters.put(KyberParameterSpec.kyber768.getName(), MLKEMParameters.ml_kem_768);
        parameters.put(KyberParameterSpec.kyber1024.getName(), MLKEMParameters.ml_kem_1024);
    }

    MLKEMKeyGenerationParameters param;
    MLKEMKeyPairGenerator engine = new MLKEMKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;
    private MLKEMParameters kyberParameters;

    public KyberKeyPairGeneratorSpi()
    {
        super("KYBER");
        this.kyberParameters = null;
    }

    protected KyberKeyPairGeneratorSpi(MLKEMParameters kyberParameters)
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
            MLKEMParameters kyberParams = (MLKEMParameters)parameters.get(name);

            param = new MLKEMKeyGenerationParameters(random, kyberParams);

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
                param = new MLKEMKeyGenerationParameters(random, kyberParameters);
            }
            else
            {
                param = new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_1024);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters)pair.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCKyberPublicKey(pub), new BCKyberPrivateKey(priv));
    }

    public static class Kyber512
        extends KyberKeyPairGeneratorSpi
    {
        public Kyber512()
        {
            super(MLKEMParameters.ml_kem_512);
        }
    }

    public static class Kyber768
        extends KyberKeyPairGeneratorSpi
    {
        public Kyber768()
        {
            super(MLKEMParameters.ml_kem_768);
        }
    }

    public static class Kyber1024
        extends KyberKeyPairGeneratorSpi
    {
        public Kyber1024()
        {
            super(MLKEMParameters.ml_kem_1024);
        }
    }
}
