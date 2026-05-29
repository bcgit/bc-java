package org.bouncycastle.pqc.jcajce.provider.sqisign;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.util.Strings;

public class SQIsignKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("sqisign_lvl1", SQIsignParameters.sqisign_lvl1);
        parameters.put("sqisign_lvl3", SQIsignParameters.sqisign_lvl3);
        parameters.put("sqisign_lvl5", SQIsignParameters.sqisign_lvl5);
        parameters.put(SQIsignParameterSpec.sqisign_lvl1.getName(), SQIsignParameters.sqisign_lvl1);
        parameters.put(SQIsignParameterSpec.sqisign_lvl3.getName(), SQIsignParameters.sqisign_lvl3);
        parameters.put(SQIsignParameterSpec.sqisign_lvl5.getName(), SQIsignParameters.sqisign_lvl5);
    }

    SQIsignKeyGenerationParameters param;
    private SQIsignParameters sqisignParameters;
    SQIsignKeyPairGenerator engine = new SQIsignKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SQIsignKeyPairGeneratorSpi()
    {
        super("SQIsign");
    }

    protected SQIsignKeyPairGeneratorSpi(SQIsignParameters sqisignParameters)
    {
        super(sqisignParameters.getName());
        this.sqisignParameters = sqisignParameters;
    }

    public void initialize(int strength, SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);

        if (name != null && parameters.containsKey(name))
        {
            param = new SQIsignKeyGenerationParameters(random, (SQIsignParameters)parameters.get(name));

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
        if (paramSpec instanceof SQIsignParameterSpec)
        {
            SQIsignParameterSpec sqisignSpec = (SQIsignParameterSpec)paramSpec;
            return sqisignSpec.getName();
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
            param = new SQIsignKeyGenerationParameters(random, SQIsignParameters.sqisign_lvl1);
            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SQIsignPublicKeyParameters pub = (SQIsignPublicKeyParameters)pair.getPublic();
        SQIsignPrivateKeyParameters priv = (SQIsignPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSQIsignPublicKey(pub), new BCSQIsignPrivateKey(priv));
    }

    public static class SQIsign_lvl1
        extends SQIsignKeyPairGeneratorSpi
    {
        public SQIsign_lvl1()
        {
            super(SQIsignParameters.sqisign_lvl1);
        }
    }

    public static class SQIsign_lvl3
        extends SQIsignKeyPairGeneratorSpi
    {
        public SQIsign_lvl3()
        {
            super(SQIsignParameters.sqisign_lvl3);
        }
    }

    public static class SQIsign_lvl5
        extends SQIsignKeyPairGeneratorSpi
    {
        public SQIsign_lvl5()
        {
            super(SQIsignParameters.sqisign_lvl5);
        }
    }
}
