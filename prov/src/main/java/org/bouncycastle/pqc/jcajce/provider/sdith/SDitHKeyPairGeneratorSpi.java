package org.bouncycastle.pqc.jcajce.provider.sdith;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.sdith.SDitHKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sdith.SDitHParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;
import org.bouncycastle.util.Strings;

public class SDitHKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("SDITH-HYPERCUBE-CAT1-GF256", SDitHParameters.sdith_hypercube_cat1_gf256);
        parameters.put("SDITH-HYPERCUBE-CAT3-GF256", SDitHParameters.sdith_hypercube_cat3_gf256);
        parameters.put("SDITH-HYPERCUBE-CAT5-GF256", SDitHParameters.sdith_hypercube_cat5_gf256);
        parameters.put("SDITH-HYPERCUBE-CAT1-P251", SDitHParameters.sdith_hypercube_cat1_p251);
        parameters.put("SDITH-HYPERCUBE-CAT3-P251", SDitHParameters.sdith_hypercube_cat3_p251);
        parameters.put("SDITH-HYPERCUBE-CAT5-P251", SDitHParameters.sdith_hypercube_cat5_p251);
        parameters.put(SDitHParameterSpec.sdith_hypercube_cat1_gf256.getName(), SDitHParameters.sdith_hypercube_cat1_gf256);
        parameters.put(SDitHParameterSpec.sdith_hypercube_cat3_gf256.getName(), SDitHParameters.sdith_hypercube_cat3_gf256);
        parameters.put(SDitHParameterSpec.sdith_hypercube_cat5_gf256.getName(), SDitHParameters.sdith_hypercube_cat5_gf256);
        parameters.put(SDitHParameterSpec.sdith_hypercube_cat1_p251.getName(), SDitHParameters.sdith_hypercube_cat1_p251);
        parameters.put(SDitHParameterSpec.sdith_hypercube_cat3_p251.getName(), SDitHParameters.sdith_hypercube_cat3_p251);
        parameters.put(SDitHParameterSpec.sdith_hypercube_cat5_p251.getName(), SDitHParameters.sdith_hypercube_cat5_p251);
        parameters.put("SDITH-THRESHOLD-CAT1-GF256", SDitHParameters.sdith_threshold_cat1_gf256);
        parameters.put("SDITH-THRESHOLD-CAT3-GF256", SDitHParameters.sdith_threshold_cat3_gf256);
        parameters.put("SDITH-THRESHOLD-CAT5-GF256", SDitHParameters.sdith_threshold_cat5_gf256);
        parameters.put("SDITH-THRESHOLD-CAT1-P251", SDitHParameters.sdith_threshold_cat1_p251);
        parameters.put("SDITH-THRESHOLD-CAT3-P251", SDitHParameters.sdith_threshold_cat3_p251);
        parameters.put("SDITH-THRESHOLD-CAT5-P251", SDitHParameters.sdith_threshold_cat5_p251);
        parameters.put(SDitHParameterSpec.sdith_threshold_cat1_gf256.getName(), SDitHParameters.sdith_threshold_cat1_gf256);
        parameters.put(SDitHParameterSpec.sdith_threshold_cat3_gf256.getName(), SDitHParameters.sdith_threshold_cat3_gf256);
        parameters.put(SDitHParameterSpec.sdith_threshold_cat5_gf256.getName(), SDitHParameters.sdith_threshold_cat5_gf256);
        parameters.put(SDitHParameterSpec.sdith_threshold_cat1_p251.getName(), SDitHParameters.sdith_threshold_cat1_p251);
        parameters.put(SDitHParameterSpec.sdith_threshold_cat3_p251.getName(), SDitHParameters.sdith_threshold_cat3_p251);
        parameters.put(SDitHParameterSpec.sdith_threshold_cat5_p251.getName(), SDitHParameters.sdith_threshold_cat5_p251);
    }

    SDitHKeyGenerationParameters param;
    private SDitHParameters sdithParameters;
    SDitHKeyPairGenerator engine = new SDitHKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SDitHKeyPairGeneratorSpi()
    {
        super("SDitH");
    }

    protected SDitHKeyPairGeneratorSpi(SDitHParameters sdithParameters)
    {
        super(sdithParameters.getName());
        this.sdithParameters = sdithParameters;
    }

    public void initialize(int strength, SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);
        if (name == null)
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }
        SDitHParameters resolved = (SDitHParameters) parameters.get(name);
        if (resolved == null)
        {
            throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
        }
        this.param = new SDitHKeyGenerationParameters(random, resolved);
        engine.init(param);
        initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof SDitHParameterSpec)
        {
            return ((SDitHParameterSpec) paramSpec).getName();
        }
        return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new SDitHKeyGenerationParameters(random,
                    sdithParameters != null ? sdithParameters : SDitHParameters.sdith_hypercube_cat1_gf256);
            engine.init(param);
            initialised = true;
        }
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SDitHPublicKeyParameters pub = (SDitHPublicKeyParameters) pair.getPublic();
        SDitHPrivateKeyParameters priv = (SDitHPrivateKeyParameters) pair.getPrivate();
        return new KeyPair(new BCSDitHPublicKey(pub), new BCSDitHPrivateKey(priv));
    }

    public static class HypercubeCat1Gf256 extends SDitHKeyPairGeneratorSpi
    {
        public HypercubeCat1Gf256()
        {
            super(SDitHParameters.sdith_hypercube_cat1_gf256);
        }
    }

    public static class HypercubeCat3Gf256 extends SDitHKeyPairGeneratorSpi
    {
        public HypercubeCat3Gf256()
        {
            super(SDitHParameters.sdith_hypercube_cat3_gf256);
        }
    }

    public static class HypercubeCat5Gf256 extends SDitHKeyPairGeneratorSpi
    {
        public HypercubeCat5Gf256()
        {
            super(SDitHParameters.sdith_hypercube_cat5_gf256);
        }
    }

    public static class HypercubeCat1P251 extends SDitHKeyPairGeneratorSpi
    {
        public HypercubeCat1P251()
        {
            super(SDitHParameters.sdith_hypercube_cat1_p251);
        }
    }

    public static class HypercubeCat3P251 extends SDitHKeyPairGeneratorSpi
    {
        public HypercubeCat3P251()
        {
            super(SDitHParameters.sdith_hypercube_cat3_p251);
        }
    }

    public static class HypercubeCat5P251 extends SDitHKeyPairGeneratorSpi
    {
        public HypercubeCat5P251()
        {
            super(SDitHParameters.sdith_hypercube_cat5_p251);
        }
    }

    public static class ThresholdCat1Gf256 extends SDitHKeyPairGeneratorSpi
    {
        public ThresholdCat1Gf256()
        {
            super(SDitHParameters.sdith_threshold_cat1_gf256);
        }
    }

    public static class ThresholdCat3Gf256 extends SDitHKeyPairGeneratorSpi
    {
        public ThresholdCat3Gf256()
        {
            super(SDitHParameters.sdith_threshold_cat3_gf256);
        }
    }

    public static class ThresholdCat5Gf256 extends SDitHKeyPairGeneratorSpi
    {
        public ThresholdCat5Gf256()
        {
            super(SDitHParameters.sdith_threshold_cat5_gf256);
        }
    }

    public static class ThresholdCat1P251 extends SDitHKeyPairGeneratorSpi
    {
        public ThresholdCat1P251()
        {
            super(SDitHParameters.sdith_threshold_cat1_p251);
        }
    }

    public static class ThresholdCat3P251 extends SDitHKeyPairGeneratorSpi
    {
        public ThresholdCat3P251()
        {
            super(SDitHParameters.sdith_threshold_cat3_p251);
        }
    }

    public static class ThresholdCat5P251 extends SDitHKeyPairGeneratorSpi
    {
        public ThresholdCat5P251()
        {
            super(SDitHParameters.sdith_threshold_cat5_p251);
        }
    }
}
