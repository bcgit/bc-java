package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.CMCEKeyPairGenerator;
import org.bouncycastle.crypto.params.CMCEKeyGenerationParameters;
import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.crypto.params.CMCEPrivateKeyParameters;
import org.bouncycastle.crypto.params.CMCEPublicKeyParameters;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

public class CMCEKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    CMCEKeyGenerationParameters param;
    CMCEKeyPairGenerator engine = new CMCEKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;
    private CMCEParameters cmceParameters;

    public CMCEKeyPairGeneratorSpi()
    {
        super("CMCE");
    }

    protected CMCEKeyPairGeneratorSpi(CMCEParameterSpec paramSpec)
    {
        super(paramSpec.getName());
        this.cmceParameters = Utils.getParameters(paramSpec.getName());

        if (param == null)
        {
            param = new CMCEKeyGenerationParameters(random, cmceParameters);
        }

        engine.init(param);
        initialised = true;
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        try
        {
            initialize(params, new BCJcaJceHelper().createSecureRandom("DEFAULT"));
        }
        catch (NoSuchAlgorithmException e)
        {
            throw Exceptions.illegalStateException("unable to find DEFAULT DRBG", e);
        }
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);

        if (name != null)
        {
            CMCEParameters cmceParams = Utils.getParameters(name);
            if (cmceParams == null)
            {
                throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
            }

            if (cmceParameters != null && !cmceParams.getName().equals(cmceParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
            }

            param = new CMCEKeyGenerationParameters(random, cmceParams);

            engine.init(param);
            initialised = true;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new CMCEKeyGenerationParameters(random, CMCEParameters.mceliece460896);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        CMCEPublicKeyParameters pub = (CMCEPublicKeyParameters)pair.getPublic();
        CMCEPrivateKeyParameters priv = (CMCEPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCCMCEPublicKey(pub), new BCCMCEPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof CMCEParameterSpec)
        {
            CMCEParameterSpec params = (CMCEParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class Mceliece460896
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece460896()
        {
            super(CMCEParameterSpec.mceliece460896);
        }
    }

    public static class Mceliece460896F
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece460896F()
        {
            super(CMCEParameterSpec.mceliece460896f);
        }
    }

    public static class Mceliece460896Pc
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece460896Pc()
        {
            super(CMCEParameterSpec.mceliece460896pc);
        }
    }

    public static class Mceliece460896Pcf
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece460896Pcf()
        {
            super(CMCEParameterSpec.mceliece460896pcf);
        }
    }

    public static class Mceliece6688128
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6688128()
        {
            super(CMCEParameterSpec.mceliece6688128);
        }
    }

    public static class Mceliece6688128F
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6688128F()
        {
            super(CMCEParameterSpec.mceliece6688128f);
        }
    }

    public static class Mceliece6688128Pc
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6688128Pc()
        {
            super(CMCEParameterSpec.mceliece6688128pc);
        }
    }

    public static class Mceliece6688128Pcf
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6688128Pcf()
        {
            super(CMCEParameterSpec.mceliece6688128pcf);
        }
    }

    public static class Mceliece6960119
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6960119()
        {
            super(CMCEParameterSpec.mceliece6960119);
        }
    }

    public static class Mceliece6960119F
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6960119F()
        {
            super(CMCEParameterSpec.mceliece6960119f);
        }
    }

    public static class Mceliece6960119Pc
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6960119Pc()
        {
            super(CMCEParameterSpec.mceliece6960119pc);
        }
    }

    public static class Mceliece6960119Pcf
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece6960119Pcf()
        {
            super(CMCEParameterSpec.mceliece6960119pcf);
        }
    }

    public static class Mceliece8192128
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece8192128()
        {
            super(CMCEParameterSpec.mceliece8192128);
        }
    }

    public static class Mceliece8192128F
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece8192128F()
        {
            super(CMCEParameterSpec.mceliece8192128f);
        }
    }

    public static class Mceliece8192128Pc
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece8192128Pc()
        {
            super(CMCEParameterSpec.mceliece8192128pc);
        }
    }

    public static class Mceliece8192128Pcf
        extends CMCEKeyPairGeneratorSpi
    {
        public Mceliece8192128Pcf()
        {
            super(CMCEParameterSpec.mceliece8192128pcf);
        }
    }
}
