package org.bouncycastle.pqc.jcajce.provider.uov;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.uov.UOVKeyPairGenerator;
import org.bouncycastle.pqc.crypto.uov.UOVKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.uov.UOVParameters;
import org.bouncycastle.pqc.crypto.uov.UOVPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.uov.UOVPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.util.Strings;

public class UOVKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private final UOVParameters lockedParameters;
    private UOVKeyGenerationParameters param;
    private final UOVKeyPairGenerator engine = new UOVKeyPairGenerator();
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public UOVKeyPairGeneratorSpi(String name)
    {
        super(name);
        this.lockedParameters = null;
    }

    protected UOVKeyPairGeneratorSpi(UOVParameterSpec paramSpec)
    {
        super(paramSpec.getName());
        this.lockedParameters = Utils.getParameters(paramSpec.getName());

        if (lockedParameters == null)
        {
            throw new IllegalStateException("no parameter set bound to spec " + paramSpec.getName());
        }
        this.param = new UOVKeyGenerationParameters(random, lockedParameters);
        engine.init(this.param);
        initialised = true;
    }

    public void initialize(int strength, SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        String name = getNameFromSpec(params);

        if (name == null)
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }

        UOVParameters uovParams = Utils.getParameters(name);
        if (uovParams == null)
        {
            throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
        }
        if (lockedParameters != null && !lockedParameters.getName().equals(uovParams.getName()))
        {
            throw new InvalidAlgorithmParameterException(
                    "key pair generator locked to " + UOVParameterSpec.fromName(lockedParameters.getName()).getName());
        }

        this.param = new UOVKeyGenerationParameters(random, uovParams);
        engine.init(this.param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            // Default to uov-Ip-classic (NIST L1, matches pqov reference default).
            param = new UOVKeyGenerationParameters(random, UOVParameters.uov_Ip);
            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        UOVPublicKeyParameters pub = (UOVPublicKeyParameters) pair.getPublic();
        UOVPrivateKeyParameters priv = (UOVPrivateKeyParameters) pair.getPrivate();
        return new KeyPair(new BCUOVPublicKey(pub), new BCUOVPrivateKey(priv));
    }

    private static String getNameFromSpec(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof UOVParameterSpec)
        {
            return ((UOVParameterSpec) paramSpec).getName();
        }
        String byUtil = SpecUtil.getNameFrom(paramSpec);
        return byUtil == null ? null : Strings.toLowerCase(byUtil);
    }

    // -------------- per-parameter-set factory classes --------------------
    public static class Generic extends UOVKeyPairGeneratorSpi
    {
        public Generic()
        {
            super("UOV");
        }
    }

    public static class Is extends UOVKeyPairGeneratorSpi
    {
        public Is()
        {
            super(UOVParameterSpec.uov_Is);
        }
    }

    public static class IsPkc extends UOVKeyPairGeneratorSpi
    {
        public IsPkc()
        {
            super(UOVParameterSpec.uov_Is_pkc);
        }
    }

    public static class IsPkcSkc extends UOVKeyPairGeneratorSpi
    {
        public IsPkcSkc()
        {
            super(UOVParameterSpec.uov_Is_pkc_skc);
        }
    }

    public static class Ip extends UOVKeyPairGeneratorSpi
    {
        public Ip()
        {
            super(UOVParameterSpec.uov_Ip);
        }
    }

    public static class IpPkc extends UOVKeyPairGeneratorSpi
    {
        public IpPkc()
        {
            super(UOVParameterSpec.uov_Ip_pkc);
        }
    }

    public static class IpPkcSkc extends UOVKeyPairGeneratorSpi
    {
        public IpPkcSkc()
        {
            super(UOVParameterSpec.uov_Ip_pkc_skc);
        }
    }

    public static class III extends UOVKeyPairGeneratorSpi
    {
        public III()
        {
            super(UOVParameterSpec.uov_III);
        }
    }

    public static class IIIPkc extends UOVKeyPairGeneratorSpi
    {
        public IIIPkc()
        {
            super(UOVParameterSpec.uov_III_pkc);
        }
    }

    public static class IIIPkcSkc extends UOVKeyPairGeneratorSpi
    {
        public IIIPkcSkc()
        {
            super(UOVParameterSpec.uov_III_pkc_skc);
        }
    }

    public static class V extends UOVKeyPairGeneratorSpi
    {
        public V()
        {
            super(UOVParameterSpec.uov_V);
        }
    }

    public static class VPkc extends UOVKeyPairGeneratorSpi
    {
        public VPkc()
        {
            super(UOVParameterSpec.uov_V_pkc);
        }
    }

    public static class VPkcSkc extends UOVKeyPairGeneratorSpi
    {
        public VPkcSkc()
        {
            super(UOVParameterSpec.uov_V_pkc_skc);
        }
    }
}
