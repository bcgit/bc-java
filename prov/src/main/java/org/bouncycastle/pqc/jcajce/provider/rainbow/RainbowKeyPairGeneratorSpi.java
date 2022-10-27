package org.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;
import org.bouncycastle.util.Strings;

public class RainbowKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(RainbowParameterSpec.rainbowIIIclassic.getName(), RainbowParameters.rainbowIIIclassic);
        parameters.put(RainbowParameterSpec.rainbowIIIcircumzenithal.getName(), RainbowParameters.rainbowIIIcircumzenithal);
        parameters.put(RainbowParameterSpec.rainbowIIIcompressed.getName(), RainbowParameters.rainbowIIIcompressed);
        parameters.put(RainbowParameterSpec.rainbowVclassic.getName(), RainbowParameters.rainbowVclassic);
        parameters.put(RainbowParameterSpec.rainbowVcircumzenithal.getName(), RainbowParameters.rainbowVcircumzenithal);
        parameters.put(RainbowParameterSpec.rainbowVcompressed.getName(), RainbowParameters.rainbowVcompressed);
    }

    private final RainbowParameters rainbowParameters;

    RainbowKeyGenerationParameters param;
    RainbowKeyPairGenerator engine = new RainbowKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public RainbowKeyPairGeneratorSpi()
    {
        super("RAINBOW");
        this.rainbowParameters = null;
    }

    protected RainbowKeyPairGeneratorSpi(RainbowParameters rainbowParameters)
    {
        super(rainbowParameters.getName());
        this.rainbowParameters = rainbowParameters;
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
            RainbowParameters rainbowParams = (RainbowParameters)parameters.get(name);

            param = new RainbowKeyGenerationParameters(random, rainbowParams);

            if (rainbowParameters != null && !rainbowParams.getName().equals(rainbowParameters.getName()))
            {
                 throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(rainbowParameters.getName()));
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
        if (paramSpec instanceof RainbowParameterSpec)
        {
            RainbowParameterSpec rainbowParams = (RainbowParameterSpec)paramSpec;
            return rainbowParams.getName();
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
            if (rainbowParameters != null)
            {
                param = new RainbowKeyGenerationParameters(random, rainbowParameters);
            }
            else
            {
                param = new RainbowKeyGenerationParameters(random, RainbowParameters.rainbowIIIclassic);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RainbowPublicKeyParameters pub = (RainbowPublicKeyParameters)pair.getPublic();
        RainbowPrivateKeyParameters priv = (RainbowPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCRainbowPublicKey(pub), new BCRainbowPrivateKey(priv));
    }

    public static class RainbowIIIclassic
        extends RainbowKeyPairGeneratorSpi
    {
        public RainbowIIIclassic()
        {
            super(RainbowParameters.rainbowIIIclassic);
        }
    }

    public static class RainbowIIIcircum
        extends RainbowKeyPairGeneratorSpi
    {
        public RainbowIIIcircum()
        {
            super(RainbowParameters.rainbowIIIcircumzenithal);
        }
    }

    public static class RainbowIIIcomp
        extends RainbowKeyPairGeneratorSpi
    {
        public RainbowIIIcomp()
        {
            super(RainbowParameters.rainbowIIIcompressed);
        }
    }

    public static class RainbowVclassic
        extends RainbowKeyPairGeneratorSpi
    {
        public RainbowVclassic()
        {
            super(RainbowParameters.rainbowVclassic);
        }
    }

    public static class RainbowVcircum
        extends RainbowKeyPairGeneratorSpi
    {
        public RainbowVcircum()
        {
            super(RainbowParameters.rainbowVcircumzenithal);
        }
    }

    public static class RainbowVcomp
        extends RainbowKeyPairGeneratorSpi
    {
        public RainbowVcomp()
        {
            super(RainbowParameters.rainbowVcompressed);
        }
    }
}
