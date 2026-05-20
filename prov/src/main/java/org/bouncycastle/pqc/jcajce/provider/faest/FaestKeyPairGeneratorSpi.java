package org.bouncycastle.pqc.jcajce.provider.faest;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.faest.FaestKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.faest.FaestKeyPairGenerator;
import org.bouncycastle.pqc.crypto.faest.FaestParameters;
import org.bouncycastle.pqc.crypto.faest.FaestPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.faest.FaestPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec;
import org.bouncycastle.util.Strings;

public class FaestKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("faest_128s", FaestParameters.faest_128s);
        parameters.put("faest_128f", FaestParameters.faest_128f);
        parameters.put("faest_192s", FaestParameters.faest_192s);
        parameters.put("faest_192f", FaestParameters.faest_192f);
        parameters.put("faest_256s", FaestParameters.faest_256s);
        parameters.put("faest_256f", FaestParameters.faest_256f);
        parameters.put("faest_em_128s", FaestParameters.faest_em_128s);
        parameters.put("faest_em_128f", FaestParameters.faest_em_128f);
        parameters.put("faest_em_192s", FaestParameters.faest_em_192s);
        parameters.put("faest_em_192f", FaestParameters.faest_em_192f);
        parameters.put("faest_em_256s", FaestParameters.faest_em_256s);
        parameters.put("faest_em_256f", FaestParameters.faest_em_256f);

        parameters.put(FaestParameterSpec.faest_128s.getName(), FaestParameters.faest_128s);
        parameters.put(FaestParameterSpec.faest_128f.getName(), FaestParameters.faest_128f);
        parameters.put(FaestParameterSpec.faest_192s.getName(), FaestParameters.faest_192s);
        parameters.put(FaestParameterSpec.faest_192f.getName(), FaestParameters.faest_192f);
        parameters.put(FaestParameterSpec.faest_256s.getName(), FaestParameters.faest_256s);
        parameters.put(FaestParameterSpec.faest_256f.getName(), FaestParameters.faest_256f);
        parameters.put(FaestParameterSpec.faest_em_128s.getName(), FaestParameters.faest_em_128s);
        parameters.put(FaestParameterSpec.faest_em_128f.getName(), FaestParameters.faest_em_128f);
        parameters.put(FaestParameterSpec.faest_em_192s.getName(), FaestParameters.faest_em_192s);
        parameters.put(FaestParameterSpec.faest_em_192f.getName(), FaestParameters.faest_em_192f);
        parameters.put(FaestParameterSpec.faest_em_256s.getName(), FaestParameters.faest_em_256s);
        parameters.put(FaestParameterSpec.faest_em_256f.getName(), FaestParameters.faest_em_256f);
    }

    FaestKeyGenerationParameters param;
    private FaestParameters faestParameters;
    FaestKeyPairGenerator engine = new FaestKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public FaestKeyPairGeneratorSpi()
    {
        super("Faest");
    }

    protected FaestKeyPairGeneratorSpi(FaestParameters faestParameters)
    {
        super(faestParameters.getName());
        this.faestParameters = faestParameters;
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
            param = new FaestKeyGenerationParameters(random, (FaestParameters)parameters.get(name));

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
        if (paramSpec instanceof FaestParameterSpec)
        {
            FaestParameterSpec faestParams = (FaestParameterSpec)paramSpec;
            return faestParams.getName();
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
            if (faestParameters != null)
            {
                param = new FaestKeyGenerationParameters(random, faestParameters);
            }
            else
            {
                param = new FaestKeyGenerationParameters(random, FaestParameters.faest_128s);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        FaestPublicKeyParameters pub = (FaestPublicKeyParameters)pair.getPublic();
        FaestPrivateKeyParameters priv = (FaestPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCFaestPublicKey(pub), new BCFaestPrivateKey(priv));
    }

    public static class FAEST_128S
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_128S()
        {
            super(FaestParameters.faest_128s);
        }
    }

    public static class FAEST_128F
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_128F()
        {
            super(FaestParameters.faest_128f);
        }
    }

    public static class FAEST_192S
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_192S()
        {
            super(FaestParameters.faest_192s);
        }
    }

    public static class FAEST_192F
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_192F()
        {
            super(FaestParameters.faest_192f);
        }
    }

    public static class FAEST_256S
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_256S()
        {
            super(FaestParameters.faest_256s);
        }
    }

    public static class FAEST_256F
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_256F()
        {
            super(FaestParameters.faest_256f);
        }
    }

    public static class FAEST_EM_128S
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_EM_128S()
        {
            super(FaestParameters.faest_em_128s);
        }
    }

    public static class FAEST_EM_128F
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_EM_128F()
        {
            super(FaestParameters.faest_em_128f);
        }
    }

    public static class FAEST_EM_192S
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_EM_192S()
        {
            super(FaestParameters.faest_em_192s);
        }
    }

    public static class FAEST_EM_192F
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_EM_192F()
        {
            super(FaestParameters.faest_em_192f);
        }
    }

    public static class FAEST_EM_256S
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_EM_256S()
        {
            super(FaestParameters.faest_em_256s);
        }
    }

    public static class FAEST_EM_256F
        extends FaestKeyPairGeneratorSpi
    {
        public FAEST_EM_256F()
        {
            super(FaestParameters.faest_em_256f);
        }
    }
}
