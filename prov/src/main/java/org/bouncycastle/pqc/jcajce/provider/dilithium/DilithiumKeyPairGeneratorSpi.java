package org.bouncycastle.pqc.jcajce.provider.dilithium;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.util.Strings;

public class DilithiumKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(DilithiumParameterSpec.dilithium2.getName(), DilithiumParameters.dilithium2);
        parameters.put(DilithiumParameterSpec.dilithium3.getName(), DilithiumParameters.dilithium3);
        parameters.put(DilithiumParameterSpec.dilithium5.getName(), DilithiumParameters.dilithium5);
    }

    private final DilithiumParameters dilithiumParameters;

    DilithiumKeyGenerationParameters param;
    DilithiumKeyPairGenerator engine = new DilithiumKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public DilithiumKeyPairGeneratorSpi()
    {
        super("DILITHIUM");
        this.dilithiumParameters = null;
    }

    protected DilithiumKeyPairGeneratorSpi(DilithiumParameters dilithiumParameters)
    {
        super(Strings.toUpperCase(dilithiumParameters.getName()));
        this.dilithiumParameters = dilithiumParameters;
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
            DilithiumParameters dilithiumParams = (DilithiumParameters)parameters.get(name);

            param = new DilithiumKeyGenerationParameters(random, dilithiumParams);

            if (dilithiumParameters != null && !dilithiumParams.getName().equals(dilithiumParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(dilithiumParameters.getName()));
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
        if (paramSpec instanceof DilithiumParameterSpec)
        {
            DilithiumParameterSpec dilithiumParams = (DilithiumParameterSpec)paramSpec;
            return dilithiumParams.getName();
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
            if (dilithiumParameters != null)
            {
                param = new DilithiumKeyGenerationParameters(random, dilithiumParameters);
            }
            else
            {
                param = new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium3);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters)pair.getPublic();
        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCDilithiumPublicKey(pub), new BCDilithiumPrivateKey(priv));
    }

    public static class Base2
        extends DilithiumKeyPairGeneratorSpi
    {
        public Base2()
            throws NoSuchAlgorithmException
        {
            super(DilithiumParameters.dilithium2);
        }
    }

    public static class Base3
        extends DilithiumKeyPairGeneratorSpi
    {
        public Base3()
            throws NoSuchAlgorithmException
        {
            super(DilithiumParameters.dilithium3);
        }
    }

    public static class Base5
        extends DilithiumKeyPairGeneratorSpi
    {
        public Base5()
            throws NoSuchAlgorithmException
        {
            super(DilithiumParameters.dilithium5);
        }
    }
}
