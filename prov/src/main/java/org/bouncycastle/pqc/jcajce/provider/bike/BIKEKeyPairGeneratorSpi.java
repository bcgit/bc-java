package org.bouncycastle.pqc.jcajce.provider.bike;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;
import org.bouncycastle.util.Strings;

public class BIKEKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put("bike128", BIKEParameters.bike128);
        parameters.put("bike192", BIKEParameters.bike192);
        parameters.put("bike256", BIKEParameters.bike256);
        parameters.put(BIKEParameterSpec.bike128.getName(), BIKEParameters.bike128);
        parameters.put(BIKEParameterSpec.bike192.getName(), BIKEParameters.bike192);
        parameters.put(BIKEParameterSpec.bike256.getName(), BIKEParameters.bike256);
    }

    BIKEKeyGenerationParameters param;
    BIKEKeyPairGenerator engine = new BIKEKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public BIKEKeyPairGeneratorSpi()
    {
        super("BIKE");
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
            param = new BIKEKeyGenerationParameters(random, (BIKEParameters)parameters.get(name));

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
        if (paramSpec instanceof BIKEParameterSpec)
        {
            BIKEParameterSpec bikeParams = (BIKEParameterSpec)paramSpec;
            return bikeParams.getName();
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
            param = new BIKEKeyGenerationParameters(random, BIKEParameters.bike128);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        BIKEPublicKeyParameters pub = (BIKEPublicKeyParameters)pair.getPublic();
        BIKEPrivateKeyParameters priv = (BIKEPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCBIKEPublicKey(pub), new BCBIKEPrivateKey(priv));
    }
}
