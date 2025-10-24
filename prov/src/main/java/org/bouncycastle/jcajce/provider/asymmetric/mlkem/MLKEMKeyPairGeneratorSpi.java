package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.util.Strings;

public class MLKEMKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    MLKEMKeyGenerationParameters param;
    MLKEMKeyPairGenerator engine = new MLKEMKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;
    private MLKEMParameters mlkemParameters;

    public MLKEMKeyPairGeneratorSpi()
    {
        super("ML-KEM");
    }

    protected MLKEMKeyPairGeneratorSpi(MLKEMParameterSpec paramSpec)
    {
        super(Strings.toUpperCase(paramSpec.getName()));
        this.mlkemParameters = Utils.getParameters(paramSpec.getName());

        if (param == null)
        {
            param = new MLKEMKeyGenerationParameters(random, mlkemParameters);
        }

        engine.init(param);
        initialised = true;
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        try
        {
            initialize(params, new BCJcaJceHelper().createSecureRandom("DEFAULT"));
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("unable to find DEFAULT DRBG");
        }
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);

        if (name != null)
        {
            MLKEMParameters mlkemParams = Utils.getParameters(name);
            if (mlkemParams == null)
            {
                throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
            }

            if (mlkemParameters != null && !mlkemParams.getName().equals(mlkemParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
            }

            param = new MLKEMKeyGenerationParameters(random, (MLKEMParameters)mlkemParams);

            engine.init(param);
            initialised = true;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters)pair.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCMLKEMPublicKey(pub), new BCMLKEMPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof MLKEMParameterSpec)
        {
            MLKEMParameterSpec params = (MLKEMParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toUpperCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class MLKEM512
            extends MLKEMKeyPairGeneratorSpi
    {
        public MLKEM512()
        {
            super(MLKEMParameterSpec.ml_kem_512);
        }
    }

    public static class MLKEM768
            extends MLKEMKeyPairGeneratorSpi
    {
        public MLKEM768()
        {
            super(MLKEMParameterSpec.ml_kem_768);
        }
    }

    public static class MLKEM1024
            extends MLKEMKeyPairGeneratorSpi
    {
        public MLKEM1024()
        {
            super(MLKEMParameterSpec.ml_kem_1024);
        }
    }
}
