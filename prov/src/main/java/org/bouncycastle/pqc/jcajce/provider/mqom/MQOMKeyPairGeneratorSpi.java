package org.bouncycastle.pqc.jcajce.provider.mqom;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;
import org.bouncycastle.util.Strings;

public class MQOMKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static final Map parameters = new HashMap();

    static
    {
        MQOMParameters[] all = new MQOMParameters[]{
                MQOMParameters.mqom2_cat1_gf2_fast_r3, MQOMParameters.mqom2_cat1_gf2_fast_r5,
                MQOMParameters.mqom2_cat1_gf2_short_r3, MQOMParameters.mqom2_cat1_gf2_short_r5,
                MQOMParameters.mqom2_cat1_gf16_fast_r3, MQOMParameters.mqom2_cat1_gf16_fast_r5,
                MQOMParameters.mqom2_cat1_gf16_short_r3, MQOMParameters.mqom2_cat1_gf16_short_r5,
                MQOMParameters.mqom2_cat1_gf256_fast_r3, MQOMParameters.mqom2_cat1_gf256_fast_r5,
                MQOMParameters.mqom2_cat1_gf256_short_r3, MQOMParameters.mqom2_cat1_gf256_short_r5,
                MQOMParameters.mqom2_cat3_gf2_fast_r3, MQOMParameters.mqom2_cat3_gf2_fast_r5,
                MQOMParameters.mqom2_cat3_gf2_short_r3, MQOMParameters.mqom2_cat3_gf2_short_r5,
                MQOMParameters.mqom2_cat3_gf16_fast_r3, MQOMParameters.mqom2_cat3_gf16_fast_r5,
                MQOMParameters.mqom2_cat3_gf16_short_r3, MQOMParameters.mqom2_cat3_gf16_short_r5,
                MQOMParameters.mqom2_cat3_gf256_fast_r3, MQOMParameters.mqom2_cat3_gf256_fast_r5,
                MQOMParameters.mqom2_cat3_gf256_short_r3, MQOMParameters.mqom2_cat3_gf256_short_r5,
                MQOMParameters.mqom2_cat5_gf2_fast_r3, MQOMParameters.mqom2_cat5_gf2_fast_r5,
                MQOMParameters.mqom2_cat5_gf2_short_r3, MQOMParameters.mqom2_cat5_gf2_short_r5,
                MQOMParameters.mqom2_cat5_gf16_fast_r3, MQOMParameters.mqom2_cat5_gf16_fast_r5,
                MQOMParameters.mqom2_cat5_gf16_short_r3, MQOMParameters.mqom2_cat5_gf16_short_r5,
                MQOMParameters.mqom2_cat5_gf256_fast_r3, MQOMParameters.mqom2_cat5_gf256_fast_r5,
                MQOMParameters.mqom2_cat5_gf256_short_r3, MQOMParameters.mqom2_cat5_gf256_short_r5
        };
        for (int i = 0; i < all.length; i++)
        {
            parameters.put(all[i].getName(), all[i]);
            // also register under the upper-case spec name so AlgorithmParameterSpec lookups succeed
            parameters.put(Strings.toUpperCase(all[i].getName()), all[i]);
        }
    }

    private final MQOMParameters mqomParameters;
    private MQOMKeyGenerationParameters param;
    private final MQOMKeyPairGenerator engine = new MQOMKeyPairGenerator();
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public MQOMKeyPairGeneratorSpi()
    {
        super("MQOM");
        this.mqomParameters = null;
    }

    protected MQOMKeyPairGeneratorSpi(MQOMParameters mqomParameters)
    {
        super(mqomParameters.getName());
        this.mqomParameters = mqomParameters;
    }

    public void initialize(int strength, SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);
        if (name != null)
        {
            MQOMParameters mqomParams = (MQOMParameters) parameters.get(name);
            if (mqomParams == null)
            {
                throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
            }
            param = new MQOMKeyGenerationParameters(random, mqomParams);
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
        if (paramSpec instanceof MQOMParameterSpec)
        {
            return ((MQOMParameterSpec) paramSpec).getName();
        }
        return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            MQOMParameters defaults = (mqomParameters != null) ? mqomParameters : MQOMParameters.mqom2_cat1_gf256_fast_r3;
            param = new MQOMKeyGenerationParameters(random, defaults);
            engine.init(param);
            initialised = true;
        }
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        MQOMPublicKeyParameters pub = (MQOMPublicKeyParameters) pair.getPublic();
        MQOMPrivateKeyParameters priv = (MQOMPrivateKeyParameters) pair.getPrivate();
        return new KeyPair(new BCMQOMPublicKey(pub), new BCMQOMPrivateKey(priv));
    }

    public static class Base extends MQOMKeyPairGeneratorSpi
    {
        public Base()
        {
            super();
        }
    }

    public static class C1Gf2Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf2Fr3()
        {
            super(MQOMParameters.mqom2_cat1_gf2_fast_r3);
        }
    }

    public static class C1Gf2Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf2Fr5()
        {
            super(MQOMParameters.mqom2_cat1_gf2_fast_r5);
        }
    }

    public static class C1Gf2Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf2Sr3()
        {
            super(MQOMParameters.mqom2_cat1_gf2_short_r3);
        }
    }

    public static class C1Gf2Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf2Sr5()
        {
            super(MQOMParameters.mqom2_cat1_gf2_short_r5);
        }
    }

    public static class C1Gf16Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf16Fr3()
        {
            super(MQOMParameters.mqom2_cat1_gf16_fast_r3);
        }
    }

    public static class C1Gf16Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf16Fr5()
        {
            super(MQOMParameters.mqom2_cat1_gf16_fast_r5);
        }
    }

    public static class C1Gf16Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf16Sr3()
        {
            super(MQOMParameters.mqom2_cat1_gf16_short_r3);
        }
    }

    public static class C1Gf16Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf16Sr5()
        {
            super(MQOMParameters.mqom2_cat1_gf16_short_r5);
        }
    }

    public static class C1Gf256Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf256Fr3()
        {
            super(MQOMParameters.mqom2_cat1_gf256_fast_r3);
        }
    }

    public static class C1Gf256Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf256Fr5()
        {
            super(MQOMParameters.mqom2_cat1_gf256_fast_r5);
        }
    }

    public static class C1Gf256Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf256Sr3()
        {
            super(MQOMParameters.mqom2_cat1_gf256_short_r3);
        }
    }

    public static class C1Gf256Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C1Gf256Sr5()
        {
            super(MQOMParameters.mqom2_cat1_gf256_short_r5);
        }
    }

    public static class C3Gf2Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf2Fr3()
        {
            super(MQOMParameters.mqom2_cat3_gf2_fast_r3);
        }
    }

    public static class C3Gf2Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf2Fr5()
        {
            super(MQOMParameters.mqom2_cat3_gf2_fast_r5);
        }
    }

    public static class C3Gf2Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf2Sr3()
        {
            super(MQOMParameters.mqom2_cat3_gf2_short_r3);
        }
    }

    public static class C3Gf2Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf2Sr5()
        {
            super(MQOMParameters.mqom2_cat3_gf2_short_r5);
        }
    }

    public static class C3Gf16Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf16Fr3()
        {
            super(MQOMParameters.mqom2_cat3_gf16_fast_r3);
        }
    }

    public static class C3Gf16Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf16Fr5()
        {
            super(MQOMParameters.mqom2_cat3_gf16_fast_r5);
        }
    }

    public static class C3Gf16Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf16Sr3()
        {
            super(MQOMParameters.mqom2_cat3_gf16_short_r3);
        }
    }

    public static class C3Gf16Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf16Sr5()
        {
            super(MQOMParameters.mqom2_cat3_gf16_short_r5);
        }
    }

    public static class C3Gf256Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf256Fr3()
        {
            super(MQOMParameters.mqom2_cat3_gf256_fast_r3);
        }
    }

    public static class C3Gf256Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf256Fr5()
        {
            super(MQOMParameters.mqom2_cat3_gf256_fast_r5);
        }
    }

    public static class C3Gf256Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf256Sr3()
        {
            super(MQOMParameters.mqom2_cat3_gf256_short_r3);
        }
    }

    public static class C3Gf256Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C3Gf256Sr5()
        {
            super(MQOMParameters.mqom2_cat3_gf256_short_r5);
        }
    }

    public static class C5Gf2Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf2Fr3()
        {
            super(MQOMParameters.mqom2_cat5_gf2_fast_r3);
        }
    }

    public static class C5Gf2Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf2Fr5()
        {
            super(MQOMParameters.mqom2_cat5_gf2_fast_r5);
        }
    }

    public static class C5Gf2Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf2Sr3()
        {
            super(MQOMParameters.mqom2_cat5_gf2_short_r3);
        }
    }

    public static class C5Gf2Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf2Sr5()
        {
            super(MQOMParameters.mqom2_cat5_gf2_short_r5);
        }
    }

    public static class C5Gf16Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf16Fr3()
        {
            super(MQOMParameters.mqom2_cat5_gf16_fast_r3);
        }
    }

    public static class C5Gf16Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf16Fr5()
        {
            super(MQOMParameters.mqom2_cat5_gf16_fast_r5);
        }
    }

    public static class C5Gf16Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf16Sr3()
        {
            super(MQOMParameters.mqom2_cat5_gf16_short_r3);
        }
    }

    public static class C5Gf16Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf16Sr5()
        {
            super(MQOMParameters.mqom2_cat5_gf16_short_r5);
        }
    }

    public static class C5Gf256Fr3 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf256Fr3()
        {
            super(MQOMParameters.mqom2_cat5_gf256_fast_r3);
        }
    }

    public static class C5Gf256Fr5 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf256Fr5()
        {
            super(MQOMParameters.mqom2_cat5_gf256_fast_r5);
        }
    }

    public static class C5Gf256Sr3 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf256Sr3()
        {
            super(MQOMParameters.mqom2_cat5_gf256_short_r3);
        }
    }

    public static class C5Gf256Sr5 extends MQOMKeyPairGeneratorSpi
    {
        public C5Gf256Sr5()
        {
            super(MQOMParameters.mqom2_cat5_gf256_short_r5);
        }
    }
}
