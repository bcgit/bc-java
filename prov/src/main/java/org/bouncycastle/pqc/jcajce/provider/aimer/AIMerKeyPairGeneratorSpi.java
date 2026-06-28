package org.bouncycastle.pqc.jcajce.provider.aimer;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyPairGenerator;
import org.bouncycastle.pqc.crypto.aimer.AIMerParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec;
import org.bouncycastle.util.Strings;

public class AIMerKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("AIMer-128f", AIMerParameters.aimer128f);
        parameters.put("AIMer-128s", AIMerParameters.aimer128s);
        parameters.put("AIMer-192f", AIMerParameters.aimer192f);
        parameters.put("AIMer-192s", AIMerParameters.aimer192s);
        parameters.put("AIMer-256f", AIMerParameters.aimer256f);
        parameters.put("AIMer-256s", AIMerParameters.aimer256s);
        parameters.put(AIMerParameterSpec.aimer128f.getName(), AIMerParameters.aimer128f);
        parameters.put(AIMerParameterSpec.aimer128s.getName(), AIMerParameters.aimer128s);
        parameters.put(AIMerParameterSpec.aimer192f.getName(), AIMerParameters.aimer192f);
        parameters.put(AIMerParameterSpec.aimer192s.getName(), AIMerParameters.aimer192s);
        parameters.put(AIMerParameterSpec.aimer256f.getName(), AIMerParameters.aimer256f);
        parameters.put(AIMerParameterSpec.aimer256s.getName(), AIMerParameters.aimer256s);
    }

    AIMerKeyGenerationParameters param;
    private AIMerParameters aimerParameters;
    AIMerKeyPairGenerator engine = new AIMerKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public AIMerKeyPairGeneratorSpi()
    {
        super("AIMer");
    }

    protected AIMerKeyPairGeneratorSpi(AIMerParameters aimerParameters)
    {
        super(aimerParameters.getName());
        this.aimerParameters = aimerParameters;
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
            param = new AIMerKeyGenerationParameters(random, (AIMerParameters)parameters.get(name));

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
        if (paramSpec instanceof AIMerParameterSpec)
        {
            AIMerParameterSpec AIMerParams = (AIMerParameterSpec)paramSpec;
            return AIMerParams.getName();
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
            param = new AIMerKeyGenerationParameters(random, AIMerParameters.aimer128f);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        AIMerPublicKeyParameters pub = (AIMerPublicKeyParameters)pair.getPublic();
        AIMerPrivateKeyParameters priv = (AIMerPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCAIMerPublicKey(pub), new BCAIMerPrivateKey(priv));
    }

    public static class AIMer_128f
        extends AIMerKeyPairGeneratorSpi
    {
        public AIMer_128f()
        {
            super(AIMerParameters.aimer128f);
        }
    }

    public static class AIMer_128s
        extends AIMerKeyPairGeneratorSpi
    {
        public AIMer_128s()
        {
            super(AIMerParameters.aimer128s);
        }
    }

    public static class AIMer_192f
        extends AIMerKeyPairGeneratorSpi
    {
        public AIMer_192f()
        {
            super(AIMerParameters.aimer192f);
        }
    }

    public static class AIMer_192s
        extends AIMerKeyPairGeneratorSpi
    {
        public AIMer_192s()
        {
            super(AIMerParameters.aimer192s);
        }
    }

    public static class AIMer_256f
        extends AIMerKeyPairGeneratorSpi
    {
        public AIMer_256f()
        {
            super(AIMerParameters.aimer256f);
        }
    }

    public static class AIMer_256s
        extends AIMerKeyPairGeneratorSpi
    {
        public AIMer_256s()
        {
            super(AIMerParameters.aimer256s);
        }
    }
}
