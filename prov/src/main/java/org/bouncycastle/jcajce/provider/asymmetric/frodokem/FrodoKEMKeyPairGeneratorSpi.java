package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.FrodoKEMKeyPairGenerator;
import org.bouncycastle.crypto.params.FrodoKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMPublicKeyParameters;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

public class FrodoKEMKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    FrodoKEMKeyGenerationParameters param;
    FrodoKEMKeyPairGenerator engine = new FrodoKEMKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;
    private FrodoKEMParameters frodoKEMParameters;

    public FrodoKEMKeyPairGeneratorSpi()
    {
        super("FRODOKEM");
    }

    protected FrodoKEMKeyPairGeneratorSpi(FrodoKEMParameterSpec paramSpec)
    {
        super(paramSpec.getName());
        this.frodoKEMParameters = Utils.getParameters(paramSpec.getName());

        if (param == null)
        {
            param = new FrodoKEMKeyGenerationParameters(random, frodoKEMParameters);
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
            throw Exceptions.illegalStateException("unable to find DEFAULT DRBG", e);
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
            FrodoKEMParameters frodoParams = Utils.getParameters(name);
            if (frodoParams == null)
            {
                throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
            }

            if (frodoKEMParameters != null && !frodoParams.getName().equals(frodoKEMParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
            }

            param = new FrodoKEMKeyGenerationParameters(random, frodoParams);

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
            param = new FrodoKEMKeyGenerationParameters(random, FrodoKEMParameters.frodokem976shake);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        FrodoKEMPublicKeyParameters pub = (FrodoKEMPublicKeyParameters)pair.getPublic();
        FrodoKEMPrivateKeyParameters priv = (FrodoKEMPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCFrodoKEMPublicKey(pub), new BCFrodoKEMPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof FrodoKEMParameterSpec)
        {
            FrodoKEMParameterSpec params = (FrodoKEMParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class Frodokem976Shake
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public Frodokem976Shake()
        {
            super(FrodoKEMParameterSpec.frodokem976shake);
        }
    }

    public static class Frodokem1344Shake
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public Frodokem1344Shake()
        {
            super(FrodoKEMParameterSpec.frodokem1344shake);
        }
    }

    public static class EFrodokem976Shake
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public EFrodokem976Shake()
        {
            super(FrodoKEMParameterSpec.efrodokem976shake);
        }
    }

    public static class EFrodokem1344Shake
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public EFrodokem1344Shake()
        {
            super(FrodoKEMParameterSpec.efrodokem1344shake);
        }
    }

    public static class Frodokem976Aes
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public Frodokem976Aes()
        {
            super(FrodoKEMParameterSpec.frodokem976aes);
        }
    }

    public static class Frodokem1344Aes
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public Frodokem1344Aes()
        {
            super(FrodoKEMParameterSpec.frodokem1344aes);
        }
    }

    public static class EFrodokem976Aes
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public EFrodokem976Aes()
        {
            super(FrodoKEMParameterSpec.efrodokem976aes);
        }
    }

    public static class EFrodokem1344Aes
        extends FrodoKEMKeyPairGeneratorSpi
    {
        public EFrodokem1344Aes()
        {
            super(FrodoKEMParameterSpec.efrodokem1344aes);
        }
    }
}
