package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.util.Strings;

public class MLDSAKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(MLDSAParameterSpec.ml_dsa_44.getName(), MLDSAParameters.ml_dsa_44);
        parameters.put(MLDSAParameterSpec.ml_dsa_65.getName(), MLDSAParameters.ml_dsa_65);
        parameters.put(MLDSAParameterSpec.ml_dsa_87.getName(), MLDSAParameters.ml_dsa_87);
        parameters.put(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), MLDSAParameters.ml_dsa_44_with_sha512);
        parameters.put(MLDSAParameterSpec.ml_dsa_65_with_sha512.getName(), MLDSAParameters.ml_dsa_65_with_sha512);
        parameters.put(MLDSAParameterSpec.ml_dsa_87_with_sha512.getName(), MLDSAParameters.ml_dsa_87_with_sha512);
    }

    private final MLDSAParameters mldsaParameters;
    MLDSAKeyGenerationParameters param;
    MLDSAKeyPairGenerator engine = new MLDSAKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public MLDSAKeyPairGeneratorSpi(String name)
    {
        super(name);
        this.mldsaParameters = null;
    }

    protected MLDSAKeyPairGeneratorSpi(MLDSAParameterSpec paramSpec)
    {
        super(Strings.toUpperCase(paramSpec.getName()));
        this.mldsaParameters = (MLDSAParameters)parameters.get(paramSpec.getName());

        if (param == null)
        {
            param = new MLDSAKeyGenerationParameters(random, mldsaParameters);
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
            MLDSAParameters mldsaParams = (MLDSAParameters)parameters.get(name);
            if (mldsaParams == null)
            {
                throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
            }
            param = new MLDSAKeyGenerationParameters(random, mldsaParams);

            if (mldsaParameters != null && !mldsaParams.getName().equals(mldsaParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + MLDSAParameterSpec.fromName(mldsaParameters.getName()).getName());
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
            if (this.getAlgorithm().startsWith("HASH"))
            {
                param = new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_87_with_sha512);
            }
            else
            {
                param = new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_87);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters)pair.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCMLDSAPublicKey(pub), new BCMLDSAPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof MLDSAParameterSpec)
        {
            MLDSAParameterSpec params = (MLDSAParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toUpperCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class Pure
        extends MLDSAKeyPairGeneratorSpi
    {
        public Pure()
            throws NoSuchAlgorithmException
        {
            super("ML-DSA");
        }
    }

    public static class MLDSA44
        extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA44()
            throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_44);
        }
    }

    public static class MLDSA65
        extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA65()
            throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_65);
        }
    }

    public static class MLDSA87
        extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA87()
            throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_87);
        }
    }

    public static class Hash
        extends MLDSAKeyPairGeneratorSpi
    {
        public Hash()
            throws NoSuchAlgorithmException
        {
            super("HASH-ML-DSA");
        }
    }

    public static class MLDSA44withSHA512
        extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA44withSHA512()
            throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_44_with_sha512);
        }
    }

    public static class MLDSA65withSHA512
        extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA65withSHA512()
            throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_65_with_sha512);
        }
    }

    public static class MLDSA87withSHA512
        extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA87withSHA512()
            throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_87_with_sha512);
        }
    }
}
