package org.bouncycastle.pqc.jcajce.provider.picnic;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyPairGenerator;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.bouncycastle.util.Strings;

public class PicnicKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(PicnicParameterSpec.picnicl1fs.getName(), PicnicParameters.picnicl1fs);
        parameters.put(PicnicParameterSpec.picnicl1ur.getName(), PicnicParameters.picnicl1ur);
        parameters.put(PicnicParameterSpec.picnicl3fs.getName(), PicnicParameters.picnicl3fs);
        parameters.put(PicnicParameterSpec.picnicl3ur.getName(), PicnicParameters.picnicl3ur);
        parameters.put(PicnicParameterSpec.picnicl5fs.getName(), PicnicParameters.picnicl5fs);
        parameters.put(PicnicParameterSpec.picnicl5ur.getName(), PicnicParameters.picnicl5ur);
        parameters.put(PicnicParameterSpec.picnic3l1.getName(), PicnicParameters.picnic3l1);
        parameters.put(PicnicParameterSpec.picnic3l3.getName(), PicnicParameters.picnic3l3);
        parameters.put(PicnicParameterSpec.picnic3l5.getName(), PicnicParameters.picnic3l5);
        parameters.put(PicnicParameterSpec.picnicl1full.getName(), PicnicParameters.picnicl1full);
        parameters.put(PicnicParameterSpec.picnicl3full.getName(), PicnicParameters.picnicl3full);
        parameters.put(PicnicParameterSpec.picnicl5full.getName(), PicnicParameters.picnicl5full);
    }

    PicnicKeyGenerationParameters param;
    PicnicKeyPairGenerator engine = new PicnicKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public PicnicKeyPairGeneratorSpi()
    {
        super("Picnic");
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
            param = new PicnicKeyGenerationParameters(random, (PicnicParameters)parameters.get(name));

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
        if (paramSpec instanceof PicnicParameterSpec)
        {
            PicnicParameterSpec frodoParams = (PicnicParameterSpec)paramSpec;
            return frodoParams.getName();
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
            param = new PicnicKeyGenerationParameters(random, PicnicParameters.picnicl3ur);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        PicnicPublicKeyParameters pub = (PicnicPublicKeyParameters)pair.getPublic();
        PicnicPrivateKeyParameters priv = (PicnicPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCPicnicPublicKey(pub), new BCPicnicPrivateKey(priv));
    }
}
