package org.bouncycastle.pqc.jcajce.provider.haetae;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.haetae.HAETAEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.haetae.HAETAEParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * {@link java.security.KeyPairGenerator} SPI for HAETAE. Construct with the
 * default constructor and call {@link #initialize(AlgorithmParameterSpec, SecureRandom)}
 * with a {@link HaetaeParameterSpec} to pick a parameter set; or use one of
 * the nested {@link HAETAE2} / {@link HAETAE3} / {@link HAETAE5} subclasses
 * which hard-pin a parameter set so callers can reach a specific variant via
 * {@code KeyPairGenerator.getInstance(spec.getName(), "BCPQC")}.
 */
public class HaetaeKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("haetae2", HAETAEParameters.haetae2);
        parameters.put("haetae3", HAETAEParameters.haetae3);
        parameters.put("haetae5", HAETAEParameters.haetae5);

        parameters.put(Strings.toLowerCase(HaetaeParameterSpec.haetae2.getName()), HAETAEParameters.haetae2);
        parameters.put(Strings.toLowerCase(HaetaeParameterSpec.haetae3.getName()), HAETAEParameters.haetae3);
        parameters.put(Strings.toLowerCase(HaetaeParameterSpec.haetae5.getName()), HAETAEParameters.haetae5);
    }

    HAETAEKeyGenerationParameters param;
    private HAETAEParameters haetaeParameters;
    HAETAEKeyPairGenerator engine = new HAETAEKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public HaetaeKeyPairGeneratorSpi()
    {
        super("Haetae");
    }

    protected HaetaeKeyPairGeneratorSpi(HAETAEParameters haetaeParameters)
    {
        super(haetaeParameters.getName());
        this.haetaeParameters = haetaeParameters;
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
            param = new HAETAEKeyGenerationParameters(random, (HAETAEParameters)parameters.get(name));

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
        if (paramSpec instanceof HaetaeParameterSpec)
        {
            HaetaeParameterSpec haetaeParams = (HaetaeParameterSpec)paramSpec;
            return Strings.toLowerCase(haetaeParams.getName());
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
            if (haetaeParameters != null)
            {
                param = new HAETAEKeyGenerationParameters(random, haetaeParameters);
            }
            else
            {
                param = new HAETAEKeyGenerationParameters(random, HAETAEParameters.haetae2);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        HAETAEPublicKeyParameters pub = (HAETAEPublicKeyParameters)pair.getPublic();
        HAETAEPrivateKeyParameters priv = (HAETAEPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCHaetaePublicKey(pub), new BCHaetaePrivateKey(priv));
    }

    public static class HAETAE2
        extends HaetaeKeyPairGeneratorSpi
    {
        public HAETAE2()
        {
            super(HAETAEParameters.haetae2);
        }
    }

    public static class HAETAE3
        extends HaetaeKeyPairGeneratorSpi
    {
        public HAETAE3()
        {
            super(HAETAEParameters.haetae3);
        }
    }

    public static class HAETAE5
        extends HaetaeKeyPairGeneratorSpi
    {
        public HAETAE5()
        {
            super(HAETAEParameters.haetae5);
        }
    }
}
