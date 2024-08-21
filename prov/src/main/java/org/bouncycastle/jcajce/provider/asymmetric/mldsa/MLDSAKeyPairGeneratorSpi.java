package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyPairGeneratorSpi;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.util.Strings;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class MLDSAKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(MLDSAParameterSpec.ml_dsa_44.getName(), DilithiumParameters.dilithium2);
        parameters.put(MLDSAParameterSpec.ml_dsa_65.getName(), DilithiumParameters.dilithium3);
        parameters.put(MLDSAParameterSpec.ml_dsa_87.getName(), DilithiumParameters.dilithium5);
    }
    private final DilithiumParameters dilithiumParameters;
    DilithiumKeyGenerationParameters param;
    DilithiumKeyPairGenerator engine = new DilithiumKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public MLDSAKeyPairGeneratorSpi()
    {
        super("MLDSA");
        this.dilithiumParameters = null;
    }

    protected MLDSAKeyPairGeneratorSpi(MLDSAParameterSpec paramSpec)
    {
        super(Strings.toUpperCase(paramSpec.getName()));
        this.dilithiumParameters = (DilithiumParameters) parameters.get(paramSpec.getName());

        if (param == null)
        {
            param = new DilithiumKeyGenerationParameters(random, dilithiumParameters);
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

        if (name != null && parameters.containsKey(name))
        {
            DilithiumParameters dilithiumParams = (DilithiumParameters)parameters.get(name);

            param = new DilithiumKeyGenerationParameters(random, (DilithiumParameters)parameters.get(name));

            if (dilithiumParameters != null && !dilithiumParams.getName().equals(dilithiumParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " +  MLDSAParameterSpec.fromName(dilithiumParameters.getName()).getName());
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
            param = new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium3);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters)pair.getPublic();
        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCMLDSAPublicKey(pub), new BCMLDSAPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof MLDSAParameterSpec)
        {
            MLDSAParameterSpec params = (MLDSAParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class MLDSA44
            extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA44()
                throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_44);
        }
    }

    public static class MLDSA65
            extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA65()
                throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_65);
        }
    }

    public static class MLDSA87
            extends MLDSAKeyPairGeneratorSpi
    {
        public MLDSA87()
                throws NoSuchAlgorithmException
        {
            super(MLDSAParameterSpec.ml_dsa_87);
        }
    }
}
