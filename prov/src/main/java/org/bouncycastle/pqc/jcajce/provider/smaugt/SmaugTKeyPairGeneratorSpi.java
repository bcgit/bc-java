package org.bouncycastle.pqc.jcajce.provider.smaugt;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.SmaugTParameterSpec;
import org.bouncycastle.util.Strings;

public class SmaugTKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(SmaugTParameterSpec.smaugt_mode1.getName(), SmaugTParameters.smaugt_mode1);
        parameters.put(SmaugTParameterSpec.smaugt_mode3.getName(), SmaugTParameters.smaugt_mode3);
        parameters.put(SmaugTParameterSpec.smaugt_mode5.getName(), SmaugTParameters.smaugt_mode5);
        parameters.put(SmaugTParameterSpec.smaugt_modet.getName(), SmaugTParameters.smaugt_modet);
    }

    private final SmaugTParameters smaugTParameters;

    SmaugTKeyGenerationParameters param;
    SmaugTKeyPairGenerator engine = new SmaugTKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SmaugTKeyPairGeneratorSpi()
    {
        super("SMAUGT");
        this.smaugTParameters = null;
    }

    protected SmaugTKeyPairGeneratorSpi(SmaugTParameters smaugTParameters)
    {
        super(smaugTParameters.getName());
        this.smaugTParameters = smaugTParameters;
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
            SmaugTParameters smaugtParams = (SmaugTParameters)parameters.get(name);

            param = new SmaugTKeyGenerationParameters(random, smaugtParams);

            if (smaugTParameters != null && !smaugtParams.getName().equals(smaugTParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(smaugTParameters.getName()));
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
        if (paramSpec instanceof SmaugTParameterSpec)
        {
            SmaugTParameterSpec smaugtParams = (SmaugTParameterSpec)paramSpec;
            return smaugtParams.getName();
        }
        else
        {
            return Strings.toUpperCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            if (smaugTParameters != null)
            {
                param = new SmaugTKeyGenerationParameters(random, smaugTParameters);
            }
            else
            {
                param = new SmaugTKeyGenerationParameters(random, SmaugTParameters.smaugt_mode1);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SmaugTPublicKeyParameters pub = (SmaugTPublicKeyParameters)pair.getPublic();
        SmaugTPrivateKeyParameters priv = (SmaugTPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSmaugTPublicKey(pub), new BCSmaugTPrivateKey(priv));
    }

    public static class Mode1
        extends SmaugTKeyPairGeneratorSpi
    {
        public Mode1()
        {
            super(SmaugTParameters.smaugt_mode1);
        }
    }

    public static class Mode3
        extends SmaugTKeyPairGeneratorSpi
    {
        public Mode3()
        {
            super(SmaugTParameters.smaugt_mode3);
        }
    }

    public static class Mode5
        extends SmaugTKeyPairGeneratorSpi
    {
        public Mode5()
        {
            super(SmaugTParameters.smaugt_mode5);
        }
    }

    public static class ModeT
        extends SmaugTKeyPairGeneratorSpi
    {
        public ModeT()
        {
            super(SmaugTParameters.smaugt_modet);
        }
    }
}
