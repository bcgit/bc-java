package org.bouncycastle.pqc.jcajce.provider.cmce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.cmce.CMCEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Strings;

public class CMCEKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(CMCEParameterSpec.mceliece348864.getName(), CMCEParameters.mceliece348864r3);
        parameters.put(CMCEParameterSpec.mceliece348864f.getName(), CMCEParameters.mceliece348864fr3);
        parameters.put(CMCEParameterSpec.mceliece460896.getName(), CMCEParameters.mceliece460896r3);
        parameters.put(CMCEParameterSpec.mceliece460896f.getName(), CMCEParameters.mceliece460896fr3);
        parameters.put(CMCEParameterSpec.mceliece6688128.getName(), CMCEParameters.mceliece6688128r3);
        parameters.put(CMCEParameterSpec.mceliece6688128f.getName(), CMCEParameters.mceliece6688128fr3);
        parameters.put(CMCEParameterSpec.mceliece6960119.getName(), CMCEParameters.mceliece6960119r3);
        parameters.put(CMCEParameterSpec.mceliece6960119f.getName(), CMCEParameters.mceliece6960119fr3);
        parameters.put(CMCEParameterSpec.mceliece8192128.getName(), CMCEParameters.mceliece8192128r3);
        parameters.put(CMCEParameterSpec.mceliece8192128f.getName(), CMCEParameters.mceliece8192128fr3);
    }
    
    CMCEKeyGenerationParameters param;
    CMCEKeyPairGenerator engine = new CMCEKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public CMCEKeyPairGeneratorSpi()
    {
        super("CMCE");
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
            param = new CMCEKeyGenerationParameters(random, (CMCEParameters)parameters.get(name));

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
        if (paramSpec instanceof CMCEParameterSpec)
        {
            CMCEParameterSpec cmceParams = (CMCEParameterSpec)paramSpec;

            return cmceParams.getName();
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
            param = new CMCEKeyGenerationParameters(random, CMCEParameters.mceliece8192128fr3);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        CMCEPublicKeyParameters pub = (CMCEPublicKeyParameters)pair.getPublic();
        CMCEPrivateKeyParameters priv = (CMCEPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCCMCEPublicKey(pub), new BCCMCEPrivateKey(priv));
    }
}
