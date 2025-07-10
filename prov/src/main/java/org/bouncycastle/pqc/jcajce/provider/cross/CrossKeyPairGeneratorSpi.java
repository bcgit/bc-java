package org.bouncycastle.pqc.jcajce.provider.cross;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.cross.CrossKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.cross.CrossKeyPairGenerator;
import org.bouncycastle.pqc.crypto.cross.CrossParameters;
import org.bouncycastle.pqc.crypto.cross.CrossPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cross.CrossPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.CrossParameterSpec;
import org.bouncycastle.util.Strings;

public class CrossKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("CROSS-RSDP-1-SMALL", CrossParameters.cross_rsdp_1_small);
        parameters.put(CrossParameterSpec.cross_rsdp_1_small.getName(), CrossParameters.cross_rsdp_1_small);

        parameters.put("CROSS-RSDP-1-BALANCED", CrossParameters.cross_rsdp_1_balanced);
        parameters.put(CrossParameterSpec.cross_rsdp_1_balanced.getName(), CrossParameters.cross_rsdp_1_balanced);

        parameters.put("CROSS-RSDP-1-FAST", CrossParameters.cross_rsdp_1_fast);
        parameters.put(CrossParameterSpec.cross_rsdp_1_fast.getName(), CrossParameters.cross_rsdp_1_fast);

        parameters.put("CROSS-RSDP-3-SMALL", CrossParameters.cross_rsdp_3_small);
        parameters.put(CrossParameterSpec.cross_rsdp_3_small.getName(), CrossParameters.cross_rsdp_3_small);

        parameters.put("CROSS-RSDP-3-BALANCED", CrossParameters.cross_rsdp_3_balanced);
        parameters.put(CrossParameterSpec.cross_rsdp_3_balanced.getName(), CrossParameters.cross_rsdp_3_balanced);

        parameters.put("CROSS-RSDP-3-FAST", CrossParameters.cross_rsdp_3_fast);
        parameters.put(CrossParameterSpec.cross_rsdp_3_fast.getName(), CrossParameters.cross_rsdp_3_fast);

        parameters.put("CROSS-RSDP-5-SMALL", CrossParameters.cross_rsdp_5_small);
        parameters.put(CrossParameterSpec.cross_rsdp_5_small.getName(), CrossParameters.cross_rsdp_5_small);

        parameters.put("CROSS-RSDP-5-BALANCED", CrossParameters.cross_rsdp_5_balanced);
        parameters.put(CrossParameterSpec.cross_rsdp_5_balanced.getName(), CrossParameters.cross_rsdp_5_balanced);

        parameters.put("CROSS-RSDP-5-FAST", CrossParameters.cross_rsdp_5_fast);
        parameters.put(CrossParameterSpec.cross_rsdp_5_fast.getName(), CrossParameters.cross_rsdp_5_fast);

        parameters.put("CROSS-RSDPG-1-SMALL", CrossParameters.cross_rsdpg_1_small);
        parameters.put(CrossParameterSpec.cross_rsdpg_1_small.getName(), CrossParameters.cross_rsdpg_1_small);

        parameters.put("CROSS-RSDPG-1-BALANCED", CrossParameters.cross_rsdpg_1_balanced);
        parameters.put(CrossParameterSpec.cross_rsdpg_1_balanced.getName(), CrossParameters.cross_rsdpg_1_balanced);

        parameters.put("CROSS-RSDPG-1-FAST", CrossParameters.cross_rsdpg_1_fast);
        parameters.put(CrossParameterSpec.cross_rsdpg_1_fast.getName(), CrossParameters.cross_rsdpg_1_fast);

        parameters.put("CROSS-RSDPG-3-SMALL", CrossParameters.cross_rsdpg_3_small);
        parameters.put(CrossParameterSpec.cross_rsdpg_3_small.getName(), CrossParameters.cross_rsdpg_3_small);

        parameters.put("CROSS-RSDPG-3-BALANCED", CrossParameters.cross_rsdpg_3_balanced);
        parameters.put(CrossParameterSpec.cross_rsdpg_3_balanced.getName(), CrossParameters.cross_rsdpg_3_balanced);

        parameters.put("CROSS-RSDPG-3-FAST", CrossParameters.cross_rsdpg_3_fast);
        parameters.put(CrossParameterSpec.cross_rsdpg_3_fast.getName(), CrossParameters.cross_rsdpg_3_fast);

        parameters.put("CROSS-RSDPG-5-SMALL", CrossParameters.cross_rsdpg_5_small);
        parameters.put(CrossParameterSpec.cross_rsdpg_5_small.getName(), CrossParameters.cross_rsdpg_5_small);

        parameters.put("CROSS-RSDPG-5-BALANCED", CrossParameters.cross_rsdpg_5_balanced);
        parameters.put(CrossParameterSpec.cross_rsdpg_5_balanced.getName(), CrossParameters.cross_rsdpg_5_balanced);

        parameters.put("CROSS-RSDPG-5-FAST", CrossParameters.cross_rsdpg_5_fast);
        parameters.put(CrossParameterSpec.cross_rsdpg_5_fast.getName(), CrossParameters.cross_rsdpg_5_fast);


    }

    CrossKeyGenerationParameters param;
    private CrossParameters crossParameters;
    CrossKeyPairGenerator engine = new CrossKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public CrossKeyPairGeneratorSpi()
    {
        super("Cross");
    }

    protected CrossKeyPairGeneratorSpi(CrossParameters crossParameters)
    {
        super(crossParameters.getName());
        this.crossParameters = crossParameters;
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
            param = new CrossKeyGenerationParameters(random, (CrossParameters)parameters.get(name));

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
        if (paramSpec instanceof CrossParameterSpec)
        {
            CrossParameterSpec CrossParams = (CrossParameterSpec)paramSpec;
            return CrossParams.getName();
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
            param = new CrossKeyGenerationParameters(random, CrossParameters.cross_rsdp_1_fast);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        CrossPublicKeyParameters pub = (CrossPublicKeyParameters)pair.getPublic();
        CrossPrivateKeyParameters priv = (CrossPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCCrossPublicKey(pub), new BCCrossPrivateKey(priv));
    }

    public static class CrossRsdp1Small
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp1Small()
        {
            super(CrossParameters.cross_rsdp_1_small);
        }
    }

    public static class CrossRsdp1Balanced
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp1Balanced()
        {
            super(CrossParameters.cross_rsdp_1_balanced);
        }
    }

    public static class CrossRsdp1Fast
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp1Fast()
        {
            super(CrossParameters.cross_rsdp_1_fast);
        }
    }

    public static class CrossRsdp3Small
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp3Small()
        {
            super(CrossParameters.cross_rsdp_3_small);
        }
    }

    public static class CrossRsdp3Balanced
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp3Balanced()
        {
            super(CrossParameters.cross_rsdp_3_balanced);
        }
    }

    public static class CrossRsdp3Fast
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp3Fast()
        {
            super(CrossParameters.cross_rsdp_3_fast);
        }
    }

    public static class CrossRsdp5Small
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp5Small()
        {
            super(CrossParameters.cross_rsdp_5_small);
        }
    }

    public static class CrossRsdp5Balanced
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp5Balanced()
        {
            super(CrossParameters.cross_rsdp_5_balanced);
        }
    }

    public static class CrossRsdp5Fast
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdp5Fast()
        {
            super(CrossParameters.cross_rsdp_5_fast);
        }
    }

    public static class CrossRsdpg1Small
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg1Small()
        {
            super(CrossParameters.cross_rsdpg_1_small);
        }
    }

    public static class CrossRsdpg1Balanced
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg1Balanced()
        {
            super(CrossParameters.cross_rsdpg_1_balanced);
        }
    }

    public static class CrossRsdpg1Fast
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg1Fast()
        {
            super(CrossParameters.cross_rsdpg_1_fast);
        }
    }

    public static class CrossRsdpg3Small
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg3Small()
        {
            super(CrossParameters.cross_rsdpg_3_small);
        }
    }

    public static class CrossRsdpg3Balanced
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg3Balanced()
        {
            super(CrossParameters.cross_rsdpg_3_balanced);
        }
    }

    public static class CrossRsdpg3Fast
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg3Fast()
        {
            super(CrossParameters.cross_rsdpg_3_fast);
        }
    }

    public static class CrossRsdpg5Small
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg5Small()
        {
            super(CrossParameters.cross_rsdpg_5_small);
        }
    }

    public static class CrossRsdpg5Balanced
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg5Balanced()
        {
            super(CrossParameters.cross_rsdpg_5_balanced);
        }
    }

    public static class CrossRsdpg5Fast
        extends CrossKeyPairGeneratorSpi
    {
        public CrossRsdpg5Fast()
        {
            super(CrossParameters.cross_rsdpg_5_fast);
        }
    }
}
