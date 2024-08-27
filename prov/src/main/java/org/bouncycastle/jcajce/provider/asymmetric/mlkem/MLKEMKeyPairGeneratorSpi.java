package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.util.Strings;

public class MLKEMKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(MLKEMParameterSpec.ml_kem_512.getName(), MLKEMParameters.ml_kem_512);
        parameters.put(MLKEMParameterSpec.ml_kem_768.getName(), MLKEMParameters.ml_kem_768);
        parameters.put(MLKEMParameterSpec.ml_kem_1024.getName(), MLKEMParameters.ml_kem_1024);
    }

    MLKEMKeyGenerationParameters param;
    MLKEMKeyPairGenerator engine = new MLKEMKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;
    private MLKEMParameters kyberParameters;

    public MLKEMKeyPairGeneratorSpi()
    {
        super("ML-KEM");
    }

    protected MLKEMKeyPairGeneratorSpi(MLKEMParameterSpec paramSpec)
    {
        super(Strings.toUpperCase(paramSpec.getName()));
        this.kyberParameters = (MLKEMParameters) parameters.get(paramSpec.getName());

        if (param == null)
        {
            param = new MLKEMKeyGenerationParameters(random, kyberParameters);
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
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {

        String name = getNameFromParams(params);

        MLKEMParameters kyberParams = (MLKEMParameters)parameters.get(name);

        if (name != null)
        {
            param = new MLKEMKeyGenerationParameters(random, (MLKEMParameters) parameters.get(name));

            if (kyberParameters != null && !kyberParams.getName().equals(kyberParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
            }

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
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
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
