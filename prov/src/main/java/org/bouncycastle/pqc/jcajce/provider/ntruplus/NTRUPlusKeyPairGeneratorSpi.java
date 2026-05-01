package org.bouncycastle.pqc.jcajce.provider.ntruplus;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.util.Strings;

public class NTRUPlusKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();

    static
    {
        parameters.put(NTRUPlusParameterSpec.ntruplus_768.getName(), NTRUPlusParameters.ntruplus_kem_768);
        parameters.put(NTRUPlusParameterSpec.ntruplus_864.getName(), NTRUPlusParameters.ntruplus_kem_864);
        parameters.put(NTRUPlusParameterSpec.ntruplus_1152.getName(), NTRUPlusParameters.ntruplus_kem_1152);
    }

    private final NTRUPlusParameters ntruplusParameters;

    NTRUPlusKeyGenerationParameters param;
    NTRUPlusKeyPairGenerator engine = new NTRUPlusKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public NTRUPlusKeyPairGeneratorSpi()
    {
        super("NTRUPLUS");
        this.ntruplusParameters = null;
    }

    protected NTRUPlusKeyPairGeneratorSpi(NTRUPlusParameters ntruplusParameters)
    {
        super(ntruplusParameters.getName());
        this.ntruplusParameters = ntruplusParameters;
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
            NTRUPlusParameters ntruplusParams = (NTRUPlusParameters)parameters.get(name);

            param = new NTRUPlusKeyGenerationParameters(random, ntruplusParams);

            if (ntruplusParameters != null && !ntruplusParams.getName().equals(ntruplusParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(ntruplusParameters.getName()));
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
        if (paramSpec instanceof NTRUPlusParameterSpec)
        {
            NTRUPlusParameterSpec ntruplusParams = (NTRUPlusParameterSpec)paramSpec;
            return ntruplusParams.getName();
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
            if (ntruplusParameters != null)
            {
                param = new NTRUPlusKeyGenerationParameters(random, ntruplusParameters);
            }
            else
            {
                param = new NTRUPlusKeyGenerationParameters(random, NTRUPlusParameters.ntruplus_kem_768);
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        NTRUPlusPublicKeyParameters pub = (NTRUPlusPublicKeyParameters)pair.getPublic();
        NTRUPlusPrivateKeyParameters priv = (NTRUPlusPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCNTRUPlusPublicKey(pub), new BCNTRUPlusPrivateKey(priv));
    }

    public static class NTRUPlus768
        extends NTRUPlusKeyPairGeneratorSpi
    {
        public NTRUPlus768()
        {
            super(NTRUPlusParameters.ntruplus_kem_768);
        }
    }

    public static class NTRUPlus864
        extends NTRUPlusKeyPairGeneratorSpi
    {
        public NTRUPlus864()
        {
            super(NTRUPlusParameters.ntruplus_kem_864);
        }
    }

    public static class NTRUPlus1152
        extends NTRUPlusKeyPairGeneratorSpi
    {
        public NTRUPlus1152()
        {
            super(NTRUPlusParameters.ntruplus_kem_864);
        }
    }
}
