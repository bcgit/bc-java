package org.bouncycastle.pqc.jcajce.provider.mayo;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mayo.MayoParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;
import org.bouncycastle.util.Strings;

public class MayoKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("MAYO_1", MayoParameters.mayo1);
        parameters.put("MAYO_2", MayoParameters.mayo2);
        parameters.put("MAYO_3", MayoParameters.mayo3);
        parameters.put("MAYO_5", MayoParameters.mayo5);
        parameters.put(MayoParameterSpec.mayo1.getName(), MayoParameters.mayo1);
        parameters.put(MayoParameterSpec.mayo2.getName(), MayoParameters.mayo2);
        parameters.put(MayoParameterSpec.mayo3.getName(), MayoParameters.mayo3);
        parameters.put(MayoParameterSpec.mayo5.getName(), MayoParameters.mayo5);
    }

    MayoKeyGenerationParameters param;
    private MayoParameters mayoParameters;
    MayoKeyPairGenerator engine = new MayoKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public MayoKeyPairGeneratorSpi()
    {
        super("Mayo");
    }

    protected MayoKeyPairGeneratorSpi(MayoParameters mayoParameters)
    {
        super(mayoParameters.getName());
        this.mayoParameters = mayoParameters;
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
            param = new MayoKeyGenerationParameters(random, (MayoParameters)parameters.get(name));

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
        if (paramSpec instanceof MayoParameterSpec)
        {
            MayoParameterSpec MayoParams = (MayoParameterSpec)paramSpec;
            return MayoParams.getName();
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
            param = new MayoKeyGenerationParameters(random, MayoParameters.mayo1);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        MayoPublicKeyParameters pub = (MayoPublicKeyParameters)pair.getPublic();
        MayoPrivateKeyParameters priv = (MayoPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCMayoPublicKey(pub), new BCMayoPrivateKey(priv));
    }

    public static class Mayo1
        extends MayoKeyPairGeneratorSpi
    {
        public Mayo1()
        {
            super(MayoParameters.mayo1);
        }
    }

    public static class Mayo2
        extends MayoKeyPairGeneratorSpi
    {
        public Mayo2()
        {
            super(MayoParameters.mayo2);
        }
    }

    public static class Mayo3
        extends MayoKeyPairGeneratorSpi
    {
        public Mayo3()
        {
            super(MayoParameters.mayo3);
        }
    }

    public static class Mayo5
        extends MayoKeyPairGeneratorSpi
    {
        public Mayo5()
        {
            super(MayoParameters.mayo5);
        }
    }
}
