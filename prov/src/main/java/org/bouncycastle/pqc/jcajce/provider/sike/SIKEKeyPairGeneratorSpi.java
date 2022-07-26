package org.bouncycastle.pqc.jcajce.provider.sike;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SIKEParameterSpec;
import org.bouncycastle.util.Strings;

public class SIKEKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(SIKEParameterSpec.sikep434.getName(), SIKEParameters.sikep434);
        parameters.put(SIKEParameterSpec.sikep503.getName(), SIKEParameters.sikep503);
        parameters.put(SIKEParameterSpec.sikep610.getName(), SIKEParameters.sikep610);
        parameters.put(SIKEParameterSpec.sikep751.getName(), SIKEParameters.sikep751);
        parameters.put(SIKEParameterSpec.sikep434_compressed.getName(), SIKEParameters.sikep434_compressed);
        parameters.put(SIKEParameterSpec.sikep503_compressed.getName(), SIKEParameters.sikep503_compressed);
        parameters.put(SIKEParameterSpec.sikep610_compressed.getName(), SIKEParameters.sikep610_compressed);
        parameters.put(SIKEParameterSpec.sikep751_compressed.getName(), SIKEParameters.sikep751_compressed);
    }

    SIKEKeyGenerationParameters param;
    SIKEKeyPairGenerator engine = new SIKEKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SIKEKeyPairGeneratorSpi()
    {
        super("SIKE");
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
            param = new SIKEKeyGenerationParameters(random, (SIKEParameters)parameters.get(name));

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
        if (paramSpec instanceof SIKEParameterSpec)
        {
            SIKEParameterSpec sikeParams = (SIKEParameterSpec)paramSpec;
            return sikeParams.getName();
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
            param = new SIKEKeyGenerationParameters(random, SIKEParameters.sikep751);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SIKEPublicKeyParameters pub = (SIKEPublicKeyParameters)pair.getPublic();
        SIKEPrivateKeyParameters priv = (SIKEPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSIKEPublicKey(pub), new BCSIKEPrivateKey(priv));
    }
}
