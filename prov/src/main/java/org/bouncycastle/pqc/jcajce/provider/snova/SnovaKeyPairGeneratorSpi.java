package org.bouncycastle.pqc.jcajce.provider.snova;


import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyPairGenerator;
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;
import org.bouncycastle.util.Strings;

public class SnovaKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("SNOVA_24_5_4_SSK", SnovaParameters.SNOVA_24_5_4_SSK);
        parameters.put("SNOVA_24_5_4_ESK", SnovaParameters.SNOVA_24_5_4_ESK);
        parameters.put("SNOVA_24_5_4_SHAKE_SSK", SnovaParameters.SNOVA_24_5_4_SHAKE_SSK);
        parameters.put("SNOVA_24_5_4_SHAKE_ESK", SnovaParameters.SNOVA_24_5_4_SHAKE_ESK);
        parameters.put("SNOVA_24_5_5_SSK", SnovaParameters.SNOVA_24_5_5_SSK);
        parameters.put("SNOVA_24_5_5_ESK", SnovaParameters.SNOVA_24_5_5_ESK);
        parameters.put("SNOVA_24_5_5_SHAKE_SSK", SnovaParameters.SNOVA_24_5_5_SHAKE_SSK);
        parameters.put("SNOVA_24_5_5_SHAKE_ESK", SnovaParameters.SNOVA_24_5_5_SHAKE_ESK);
        parameters.put("SNOVA_25_8_3_SSK", SnovaParameters.SNOVA_25_8_3_SSK);
        parameters.put("SNOVA_25_8_3_ESK", SnovaParameters.SNOVA_25_8_3_ESK);
        parameters.put("SNOVA_25_8_3_SHAKE_SSK", SnovaParameters.SNOVA_25_8_3_SHAKE_SSK);
        parameters.put("SNOVA_25_8_3_SHAKE_ESK", SnovaParameters.SNOVA_25_8_3_SHAKE_ESK);
        parameters.put("SNOVA_29_6_5_SSK", SnovaParameters.SNOVA_29_6_5_SSK);
        parameters.put("SNOVA_29_6_5_ESK", SnovaParameters.SNOVA_29_6_5_ESK);
        parameters.put("SNOVA_29_6_5_SHAKE_SSK", SnovaParameters.SNOVA_29_6_5_SHAKE_SSK);
        parameters.put("SNOVA_29_6_5_SHAKE_ESK", SnovaParameters.SNOVA_29_6_5_SHAKE_ESK);
        parameters.put("SNOVA_37_8_4_SSK", SnovaParameters.SNOVA_37_8_4_SSK);
        parameters.put("SNOVA_37_8_4_ESK", SnovaParameters.SNOVA_37_8_4_ESK);
        parameters.put("SNOVA_37_8_4_SHAKE_SSK", SnovaParameters.SNOVA_37_8_4_SHAKE_SSK);
        parameters.put("SNOVA_37_8_4_SHAKE_ESK", SnovaParameters.SNOVA_37_8_4_SHAKE_ESK);
        parameters.put("SNOVA_37_17_2_SSK", SnovaParameters.SNOVA_37_17_2_SSK);
        parameters.put("SNOVA_37_17_2_ESK", SnovaParameters.SNOVA_37_17_2_ESK);
        parameters.put("SNOVA_37_17_2_SHAKE_SSK", SnovaParameters.SNOVA_37_17_2_SHAKE_SSK);
        parameters.put("SNOVA_37_17_2_SHAKE_ESK", SnovaParameters.SNOVA_37_17_2_SHAKE_ESK);
        parameters.put("SNOVA_49_11_3_SSK", SnovaParameters.SNOVA_49_11_3_SSK);
        parameters.put("SNOVA_49_11_3_ESK", SnovaParameters.SNOVA_49_11_3_ESK);
        parameters.put("SNOVA_49_11_3_SHAKE_SSK", SnovaParameters.SNOVA_49_11_3_SHAKE_SSK);
        parameters.put("SNOVA_49_11_3_SHAKE_ESK", SnovaParameters.SNOVA_49_11_3_SHAKE_ESK);
        parameters.put("SNOVA_56_25_2_SSK", SnovaParameters.SNOVA_56_25_2_SSK);
        parameters.put("SNOVA_56_25_2_ESK", SnovaParameters.SNOVA_56_25_2_ESK);
        parameters.put("SNOVA_56_25_2_SHAKE_SSK", SnovaParameters.SNOVA_56_25_2_SHAKE_SSK);
        parameters.put("SNOVA_56_25_2_SHAKE_ESK", SnovaParameters.SNOVA_56_25_2_SHAKE_ESK);
        parameters.put("SNOVA_60_10_4_SSK", SnovaParameters.SNOVA_60_10_4_SSK);
        parameters.put("SNOVA_60_10_4_ESK", SnovaParameters.SNOVA_60_10_4_ESK);
        parameters.put("SNOVA_60_10_4_SHAKE_SSK", SnovaParameters.SNOVA_60_10_4_SHAKE_SSK);
        parameters.put("SNOVA_60_10_4_SHAKE_ESK", SnovaParameters.SNOVA_60_10_4_SHAKE_ESK);
        parameters.put("SNOVA_66_15_3_SSK", SnovaParameters.SNOVA_66_15_3_SSK);
        parameters.put("SNOVA_66_15_3_ESK", SnovaParameters.SNOVA_66_15_3_ESK);
        parameters.put("SNOVA_66_15_3_SHAKE_SSK", SnovaParameters.SNOVA_66_15_3_SHAKE_SSK);
        parameters.put("SNOVA_66_15_3_SHAKE_ESK", SnovaParameters.SNOVA_66_15_3_SHAKE_ESK);
        parameters.put("SNOVA_75_33_2_SSK", SnovaParameters.SNOVA_75_33_2_SSK);
        parameters.put("SNOVA_75_33_2_ESK", SnovaParameters.SNOVA_75_33_2_ESK);
        parameters.put("SNOVA_75_33_2_SHAKE_SSK", SnovaParameters.SNOVA_75_33_2_SHAKE_SSK);
        parameters.put("SNOVA_75_33_2_SHAKE_ESK", SnovaParameters.SNOVA_75_33_2_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_4_SSK.getName(), SnovaParameters.SNOVA_24_5_4_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_4_ESK.getName(), SnovaParameters.SNOVA_24_5_4_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_4_SHAKE_SSK.getName(), SnovaParameters.SNOVA_24_5_4_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_4_SHAKE_ESK.getName(), SnovaParameters.SNOVA_24_5_4_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_5_SSK.getName(), SnovaParameters.SNOVA_24_5_5_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_5_ESK.getName(), SnovaParameters.SNOVA_24_5_5_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_5_SHAKE_SSK.getName(), SnovaParameters.SNOVA_24_5_5_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_24_5_5_SHAKE_ESK.getName(), SnovaParameters.SNOVA_24_5_5_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_25_8_3_SSK.getName(), SnovaParameters.SNOVA_25_8_3_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_25_8_3_ESK.getName(), SnovaParameters.SNOVA_25_8_3_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_25_8_3_SHAKE_SSK.getName(), SnovaParameters.SNOVA_25_8_3_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_25_8_3_SHAKE_ESK.getName(), SnovaParameters.SNOVA_25_8_3_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_29_6_5_SSK.getName(), SnovaParameters.SNOVA_29_6_5_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_29_6_5_ESK.getName(), SnovaParameters.SNOVA_29_6_5_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_29_6_5_SHAKE_SSK.getName(), SnovaParameters.SNOVA_29_6_5_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_29_6_5_SHAKE_ESK.getName(), SnovaParameters.SNOVA_29_6_5_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_37_8_4_SSK.getName(), SnovaParameters.SNOVA_37_8_4_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_37_8_4_ESK.getName(), SnovaParameters.SNOVA_37_8_4_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_37_8_4_SHAKE_SSK.getName(), SnovaParameters.SNOVA_37_8_4_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_37_8_4_SHAKE_ESK.getName(), SnovaParameters.SNOVA_37_8_4_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_37_17_2_SSK.getName(), SnovaParameters.SNOVA_37_17_2_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_37_17_2_ESK.getName(), SnovaParameters.SNOVA_37_17_2_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_37_17_2_SHAKE_SSK.getName(), SnovaParameters.SNOVA_37_17_2_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_37_17_2_SHAKE_ESK.getName(), SnovaParameters.SNOVA_37_17_2_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_49_11_3_SSK.getName(), SnovaParameters.SNOVA_49_11_3_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_49_11_3_ESK.getName(), SnovaParameters.SNOVA_49_11_3_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_49_11_3_SHAKE_SSK.getName(), SnovaParameters.SNOVA_49_11_3_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_49_11_3_SHAKE_ESK.getName(), SnovaParameters.SNOVA_49_11_3_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_56_25_2_SSK.getName(), SnovaParameters.SNOVA_56_25_2_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_56_25_2_ESK.getName(), SnovaParameters.SNOVA_56_25_2_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_56_25_2_SHAKE_SSK.getName(), SnovaParameters.SNOVA_56_25_2_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_56_25_2_SHAKE_ESK.getName(), SnovaParameters.SNOVA_56_25_2_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_60_10_4_SSK.getName(), SnovaParameters.SNOVA_60_10_4_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_60_10_4_ESK.getName(), SnovaParameters.SNOVA_60_10_4_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_60_10_4_SHAKE_SSK.getName(), SnovaParameters.SNOVA_60_10_4_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_60_10_4_SHAKE_ESK.getName(), SnovaParameters.SNOVA_60_10_4_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_66_15_3_SSK.getName(), SnovaParameters.SNOVA_66_15_3_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_66_15_3_ESK.getName(), SnovaParameters.SNOVA_66_15_3_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_66_15_3_SHAKE_SSK.getName(), SnovaParameters.SNOVA_66_15_3_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_66_15_3_SHAKE_ESK.getName(), SnovaParameters.SNOVA_66_15_3_SHAKE_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_75_33_2_SSK.getName(), SnovaParameters.SNOVA_75_33_2_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_75_33_2_ESK.getName(), SnovaParameters.SNOVA_75_33_2_ESK);
        parameters.put(SnovaParameterSpec.SNOVA_75_33_2_SHAKE_SSK.getName(), SnovaParameters.SNOVA_75_33_2_SHAKE_SSK);
        parameters.put(SnovaParameterSpec.SNOVA_75_33_2_SHAKE_ESK.getName(), SnovaParameters.SNOVA_75_33_2_SHAKE_ESK);
    }

    SnovaKeyGenerationParameters param;
    private SnovaParameters snovaParameters;
    SnovaKeyPairGenerator engine = new SnovaKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SnovaKeyPairGeneratorSpi()
    {
        super("Snova");
    }

    protected SnovaKeyPairGeneratorSpi(SnovaParameters SnovaParameters)
    {
        super(SnovaParameters.getName());
        this.snovaParameters = SnovaParameters;
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
            param = new SnovaKeyGenerationParameters(random, (SnovaParameters)parameters.get(name));

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
        if (paramSpec instanceof SnovaParameterSpec)
        {
            SnovaParameterSpec SnovaParams = (SnovaParameterSpec)paramSpec;
            return SnovaParams.getName();
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
            param = new SnovaKeyGenerationParameters(random, SnovaParameters.SNOVA_24_5_4_SSK);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SnovaPublicKeyParameters pub = (SnovaPublicKeyParameters)pair.getPublic();
        SnovaPrivateKeyParameters priv = (SnovaPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSnovaPublicKey(pub), new BCSnovaPrivateKey(priv));
    }

    public static class SNOVA_24_5_4_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_4_SSK()
        {
            super(SnovaParameters.SNOVA_24_5_4_SSK);
        }
    }

    public static class SNOVA_24_5_4_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_4_ESK()
        {
            super(SnovaParameters.SNOVA_24_5_4_ESK);
        }
    }

    public static class SNOVA_24_5_4_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_4_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_24_5_4_SHAKE_SSK);
        }
    }

    public static class SNOVA_24_5_4_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_4_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_24_5_4_SHAKE_ESK);
        }
    }

    public static class SNOVA_24_5_5_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_5_SSK()
        {
            super(SnovaParameters.SNOVA_24_5_5_SSK);
        }
    }

    public static class SNOVA_24_5_5_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_5_ESK()
        {
            super(SnovaParameters.SNOVA_24_5_5_ESK);
        }
    }

    public static class SNOVA_24_5_5_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_5_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_24_5_5_SHAKE_SSK);
        }
    }

    public static class SNOVA_24_5_5_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_24_5_5_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_24_5_5_SHAKE_ESK);
        }
    }

    public static class SNOVA_25_8_3_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_25_8_3_SSK()
        {
            super(SnovaParameters.SNOVA_25_8_3_SSK);
        }
    }

    public static class SNOVA_25_8_3_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_25_8_3_ESK()
        {
            super(SnovaParameters.SNOVA_25_8_3_ESK);
        }
    }

    public static class SNOVA_25_8_3_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_25_8_3_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_25_8_3_SHAKE_SSK);
        }
    }

    public static class SNOVA_25_8_3_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_25_8_3_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_25_8_3_SHAKE_ESK);
        }
    }

    public static class SNOVA_29_6_5_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_29_6_5_SSK()
        {
            super(SnovaParameters.SNOVA_29_6_5_SSK);
        }
    }

    public static class SNOVA_29_6_5_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_29_6_5_ESK()
        {
            super(SnovaParameters.SNOVA_29_6_5_ESK);
        }
    }

    public static class SNOVA_29_6_5_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_29_6_5_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_29_6_5_SHAKE_SSK);
        }
    }

    public static class SNOVA_29_6_5_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_29_6_5_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_29_6_5_SHAKE_ESK);
        }
    }

    public static class SNOVA_37_8_4_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_8_4_SSK()
        {
            super(SnovaParameters.SNOVA_37_8_4_SSK);
        }
    }

    public static class SNOVA_37_8_4_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_8_4_ESK()
        {
            super(SnovaParameters.SNOVA_37_8_4_ESK);
        }
    }

    public static class SNOVA_37_8_4_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_8_4_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_37_8_4_SHAKE_SSK);
        }
    }

    public static class SNOVA_37_8_4_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_8_4_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_37_8_4_SHAKE_ESK);
        }
    }

    public static class SNOVA_37_17_2_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_17_2_SSK()
        {
            super(SnovaParameters.SNOVA_37_17_2_SSK);
        }
    }

    public static class SNOVA_37_17_2_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_17_2_ESK()
        {
            super(SnovaParameters.SNOVA_37_17_2_ESK);
        }
    }

    public static class SNOVA_37_17_2_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_17_2_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_37_17_2_SHAKE_SSK);
        }
    }

    public static class SNOVA_37_17_2_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_37_17_2_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_37_17_2_SHAKE_ESK);
        }
    }

    public static class SNOVA_49_11_3_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_49_11_3_SSK()
        {
            super(SnovaParameters.SNOVA_49_11_3_SSK);
        }
    }

    public static class SNOVA_49_11_3_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_49_11_3_ESK()
        {
            super(SnovaParameters.SNOVA_49_11_3_ESK);
        }
    }

    public static class SNOVA_49_11_3_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_49_11_3_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_49_11_3_SHAKE_SSK);
        }
    }

    public static class SNOVA_49_11_3_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_49_11_3_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_49_11_3_SHAKE_ESK);
        }
    }

    public static class SNOVA_56_25_2_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_56_25_2_SSK()
        {
            super(SnovaParameters.SNOVA_56_25_2_SSK);
        }
    }

    public static class SNOVA_56_25_2_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_56_25_2_ESK()
        {
            super(SnovaParameters.SNOVA_56_25_2_ESK);
        }
    }

    public static class SNOVA_56_25_2_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_56_25_2_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_56_25_2_SHAKE_SSK);
        }
    }

    public static class SNOVA_56_25_2_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_56_25_2_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_56_25_2_SHAKE_ESK);
        }
    }

    public static class SNOVA_60_10_4_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_60_10_4_SSK()
        {
            super(SnovaParameters.SNOVA_60_10_4_SSK);
        }
    }

    public static class SNOVA_60_10_4_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_60_10_4_ESK()
        {
            super(SnovaParameters.SNOVA_60_10_4_ESK);
        }
    }

    public static class SNOVA_60_10_4_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_60_10_4_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_60_10_4_SHAKE_SSK);
        }
    }

    public static class SNOVA_60_10_4_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_60_10_4_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_60_10_4_SHAKE_ESK);
        }
    }

    public static class SNOVA_66_15_3_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_66_15_3_SSK()
        {
            super(SnovaParameters.SNOVA_66_15_3_SSK);
        }
    }

    public static class SNOVA_66_15_3_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_66_15_3_ESK()
        {
            super(SnovaParameters.SNOVA_66_15_3_ESK);
        }
    }

    public static class SNOVA_66_15_3_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_66_15_3_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_66_15_3_SHAKE_SSK);
        }
    }

    public static class SNOVA_66_15_3_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_66_15_3_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_66_15_3_SHAKE_ESK);
        }
    }

    public static class SNOVA_75_33_2_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_75_33_2_SSK()
        {
            super(SnovaParameters.SNOVA_75_33_2_SSK);
        }
    }

    public static class SNOVA_75_33_2_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_75_33_2_ESK()
        {
            super(SnovaParameters.SNOVA_75_33_2_ESK);
        }
    }

    public static class SNOVA_75_33_2_SHAKE_SSK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_75_33_2_SHAKE_SSK()
        {
            super(SnovaParameters.SNOVA_75_33_2_SHAKE_SSK);
        }
    }

    public static class SNOVA_75_33_2_SHAKE_ESK
        extends SnovaKeyPairGeneratorSpi
    {
        public SNOVA_75_33_2_SHAKE_ESK()
        {
            super(SnovaParameters.SNOVA_75_33_2_SHAKE_ESK);
        }
    }
}

