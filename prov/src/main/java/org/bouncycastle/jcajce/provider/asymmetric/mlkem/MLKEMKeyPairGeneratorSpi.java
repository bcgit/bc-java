package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.util.Strings;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class MLKEMKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(MLKEMParameterSpec.ml_kem_512.getName(), KyberParameters.kyber512);
        parameters.put(MLKEMParameterSpec.ml_kem_768.getName(), KyberParameters.kyber768);
        parameters.put(MLKEMParameterSpec.ml_kem_1024.getName(), KyberParameters.kyber1024);
    }

    KyberKeyGenerationParameters param;
    KyberKeyPairGenerator engine = new KyberKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;
    private KyberParameters kyberParameters;

    public MLKEMKeyPairGeneratorSpi()
    {
        super("MLKEM");
    }

    protected MLKEMKeyPairGeneratorSpi(MLKEMParameterSpec paramSpec)
    {
        super(Strings.toUpperCase(paramSpec.getName()));
        this.kyberParameters = (KyberParameters) parameters.get(paramSpec.getName());

        if (param == null)
        {
            param = new KyberKeyGenerationParameters(random, kyberParameters);
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
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {

        String name = getNameFromParams(params);

        KyberParameters kyberParams = (KyberParameters)parameters.get(name);

        if (name != null)
        {
            param = new KyberKeyGenerationParameters(random, (KyberParameters) parameters.get(name));

            if (kyberParameters != null && !kyberParams.getName().equals(kyberParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
            }

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
            param = new KyberKeyGenerationParameters(random, KyberParameters.kyber768);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        KyberPublicKeyParameters pub = (KyberPublicKeyParameters)pair.getPublic();
        KyberPrivateKeyParameters priv = (KyberPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCMLKEMPublicKey(pub), new BCMLKEMPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof MLKEMParameterSpec)
        {
            MLKEMParameterSpec params = (MLKEMParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class MLKEM512
            extends MLKEMKeyPairGeneratorSpi
    {
        public MLKEM512()
        {
            super(MLKEMParameterSpec.ml_kem_512);
        }
    }

    public static class MLKEM768
            extends MLKEMKeyPairGeneratorSpi
    {
        public MLKEM768()
        {
            super(MLKEMParameterSpec.ml_kem_768);
        }
    }

    public static class MLKEM1024
            extends MLKEMKeyPairGeneratorSpi
    {
        public MLKEM1024()
        {
            super(MLKEMParameterSpec.ml_kem_1024);
        }
    }
}
