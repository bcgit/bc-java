package org.bouncycastle.pqc.jcajce.provider.mirath;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.mirath.MirathKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mirath.MirathParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.MirathParameterSpec;
import org.bouncycastle.util.Strings;

public class MirathKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("Mirath_1a_fast", MirathParameters.mirath_1a_fast);
        parameters.put("Mirath_1a_short", MirathParameters.mirath_1a_short);
        parameters.put("Mirath_1b_fast", MirathParameters.mirath_1b_fast);
        parameters.put("Mirath_1b_short", MirathParameters.mirath_1b_short);
        parameters.put(MirathParameterSpec.Mirath_1a_fast.getName(), MirathParameters.mirath_1a_fast);
        parameters.put(MirathParameterSpec.Mirath_1a_short.getName(), MirathParameters.mirath_1a_short);
        parameters.put(MirathParameterSpec.Mirath_1b_fast.getName(), MirathParameters.mirath_1b_fast);
        parameters.put(MirathParameterSpec.Mirath_1b_short.getName(), MirathParameters.mirath_1b_short);
        parameters.put("Mirath_3a_fast", MirathParameters.mirath_3a_fast);
        parameters.put("Mirath_3a_short", MirathParameters.mirath_3a_short);
        parameters.put("Mirath_3b_fast", MirathParameters.mirath_3b_fast);
        parameters.put("Mirath_3b_short", MirathParameters.mirath_3b_short);
        parameters.put(MirathParameterSpec.Mirath_3a_fast.getName(), MirathParameters.mirath_3a_fast);
        parameters.put(MirathParameterSpec.Mirath_3a_short.getName(), MirathParameters.mirath_3a_short);
        parameters.put(MirathParameterSpec.Mirath_3b_fast.getName(), MirathParameters.mirath_3b_fast);
        parameters.put(MirathParameterSpec.Mirath_3b_short.getName(), MirathParameters.mirath_3b_short);
        parameters.put("Mirath_5a_fast", MirathParameters.mirath_5a_fast);
        parameters.put("Mirath_5a_short", MirathParameters.mirath_5a_short);
        parameters.put("Mirath_5b_fast", MirathParameters.mirath_5b_fast);
        parameters.put("Mirath_5b_short", MirathParameters.mirath_5b_short);
        parameters.put(MirathParameterSpec.Mirath_5a_fast.getName(), MirathParameters.mirath_5a_fast);
        parameters.put(MirathParameterSpec.Mirath_5a_short.getName(), MirathParameters.mirath_5a_short);
        parameters.put(MirathParameterSpec.Mirath_5b_fast.getName(), MirathParameters.mirath_5b_fast);
        parameters.put(MirathParameterSpec.Mirath_5b_short.getName(), MirathParameters.mirath_5b_short);
    }

    MirathKeyGenerationParameters param;
    private MirathParameters mirathParameters;
    MirathKeyPairGenerator engine = new MirathKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public MirathKeyPairGeneratorSpi()
    {
        super("Mirath");
    }

    protected MirathKeyPairGeneratorSpi(MirathParameters MirathParameters)
    {
        super(MirathParameters.getName());
        this.mirathParameters = MirathParameters;
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
            param = new MirathKeyGenerationParameters(random, (MirathParameters)parameters.get(name));

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
        if (paramSpec instanceof MirathParameterSpec)
        {
            MirathParameterSpec MirathParams = (MirathParameterSpec)paramSpec;
            return MirathParams.getName();
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
            param = new MirathKeyGenerationParameters(random, MirathParameters.mirath_1a_fast);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        MirathPublicKeyParameters pub = (MirathPublicKeyParameters)pair.getPublic();
        MirathPrivateKeyParameters priv = (MirathPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCMirathPublicKey(pub), new BCMirathPrivateKey(priv));
    }

    public static class Mirath_1a_fast
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_1a_fast()
        {
            super(MirathParameters.mirath_1a_fast);
        }
    }

    public static class Mirath_1a_short
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_1a_short()
        {
            super(MirathParameters.mirath_1a_short);
        }
    }

    public static class Mirath_1b_fast
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_1b_fast()
        {
            super(MirathParameters.mirath_1b_fast);
        }
    }

    public static class Mirath_1b_short
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_1b_short()
        {
            super(MirathParameters.mirath_1b_short);
        }
    }

    public static class Mirath_3a_fast
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_3a_fast()
        {
            super(MirathParameters.mirath_3a_fast);
        }
    }

    public static class Mirath_3a_short
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_3a_short()
        {
            super(MirathParameters.mirath_3a_short);
        }
    }

    public static class Mirath_3b_fast
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_3b_fast()
        {
            super(MirathParameters.mirath_3b_fast);
        }
    }

    public static class Mirath_3b_short
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_3b_short()
        {
            super(MirathParameters.mirath_3b_short);
        }
    }

    public static class Mirath_5a_fast
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_5a_fast()
        {
            super(MirathParameters.mirath_5a_fast);
        }
    }

    public static class Mirath_5a_short
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_5a_short()
        {
            super(MirathParameters.mirath_5a_short);
        }
    }

    public static class Mirath_5b_fast
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_5b_fast()
        {
            super(MirathParameters.mirath_5b_fast);
        }
    }

    public static class Mirath_5b_short
        extends MirathKeyPairGeneratorSpi
    {
        public Mirath_5b_short()
        {
            super(MirathParameters.mirath_5b_short);
        }
    }
}
