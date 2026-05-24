package org.bouncycastle.pqc.jcajce.provider.hawk;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.hawk.HawkKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.HawkParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * {@link java.security.KeyPairGenerator} SPI for Hawk. Construct with the
 * default constructor and call {@link #initialize(AlgorithmParameterSpec, SecureRandom)}
 * with a {@link HawkParameterSpec} to pick a parameter set; or use one of the
 * nested {@link HAWK_256} / {@link HAWK_512} / {@link HAWK_1024} subclasses
 * which hard-pin a parameter set so callers can reach a specific variant via
 * {@code KeyPairGenerator.getInstance(spec.getName(), "BCPQC")}.
 */
public class HawkKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("hawk-256", HawkParameters.Hawk_256);
        parameters.put("hawk-512", HawkParameters.Hawk_512);
        parameters.put("hawk-1024", HawkParameters.Hawk_1024);

        parameters.put(HawkParameterSpec.hawk_256.getName(), HawkParameters.Hawk_256);
        parameters.put(HawkParameterSpec.hawk_512.getName(), HawkParameters.Hawk_512);
        parameters.put(HawkParameterSpec.hawk_1024.getName(), HawkParameters.Hawk_1024);
    }

    HawkKeyGenerationParameters param;
    private HawkParameters hawkParameters;
    HawkKeyPairGenerator engine = new HawkKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public HawkKeyPairGeneratorSpi()
    {
        super("Hawk");
    }

    protected HawkKeyPairGeneratorSpi(HawkParameters hawkParameters)
    {
        super(hawkParameters.getName());
        this.hawkParameters = hawkParameters;
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
            param = new HawkKeyGenerationParameters(random, (HawkParameters)parameters.get(name));

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
        if (paramSpec instanceof HawkParameterSpec)
        {
            HawkParameterSpec hawkParams = (HawkParameterSpec)paramSpec;
            return hawkParams.getName();
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
            if (hawkParameters != null)
            {
                param = new HawkKeyGenerationParameters(random, hawkParameters);
            }
            else
            {
                param = new HawkKeyGenerationParameters(random, HawkParameters.Hawk_256);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        HawkPublicKeyParameters pub = (HawkPublicKeyParameters)pair.getPublic();
        HawkPrivateKeyParameters priv = (HawkPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCHawkPublicKey(pub), new BCHawkPrivateKey(priv));
    }

    public static class HAWK_256
        extends HawkKeyPairGeneratorSpi
    {
        public HAWK_256()
        {
            super(HawkParameters.Hawk_256);
        }
    }

    public static class HAWK_512
        extends HawkKeyPairGeneratorSpi
    {
        public HAWK_512()
        {
            super(HawkParameters.Hawk_512);
        }
    }

    public static class HAWK_1024
        extends HawkKeyPairGeneratorSpi
    {
        public HAWK_1024()
        {
            super(HawkParameters.Hawk_1024);
        }
    }
}
