package org.bouncycastle.pqc.jcajce.provider.sphincsplus;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

public class SPHINCSPlusKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(SPHINCSPlusParameterSpec.sha256_128f.getName(), SPHINCSPlusParameters.sha256_128f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_128s.getName(), SPHINCSPlusParameters.sha256_128s);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192f.getName(), SPHINCSPlusParameters.sha256_192f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192s.getName(), SPHINCSPlusParameters.sha256_192s);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256f.getName(), SPHINCSPlusParameters.sha256_256f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256s.getName(), SPHINCSPlusParameters.sha256_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.sha256_128f_simple.getName(), SPHINCSPlusParameters.sha256_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_128s_simple.getName(), SPHINCSPlusParameters.sha256_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192f_simple.getName(), SPHINCSPlusParameters.sha256_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192s_simple.getName(), SPHINCSPlusParameters.sha256_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256f_simple.getName(), SPHINCSPlusParameters.sha256_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256s_simple.getName(), SPHINCSPlusParameters.sha256_256s_simple);
        
        parameters.put(SPHINCSPlusParameterSpec.shake256_128f.getName(), SPHINCSPlusParameters.shake256_128f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128s.getName(), SPHINCSPlusParameters.shake256_128s);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192f.getName(), SPHINCSPlusParameters.shake256_192f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192s.getName(), SPHINCSPlusParameters.shake256_192s);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256f.getName(), SPHINCSPlusParameters.shake256_256f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256s.getName(), SPHINCSPlusParameters.shake256_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.shake256_128f_simple.getName(), SPHINCSPlusParameters.shake256_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128s_simple.getName(), SPHINCSPlusParameters.shake256_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192f_simple.getName(), SPHINCSPlusParameters.shake256_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192s_simple.getName(), SPHINCSPlusParameters.shake256_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256f_simple.getName(), SPHINCSPlusParameters.shake256_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256s_simple.getName(), SPHINCSPlusParameters.shake256_256s_simple);
    }

    SPHINCSPlusKeyGenerationParameters param;
    SPHINCSPlusKeyPairGenerator engine = new SPHINCSPlusKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SPHINCSPlusKeyPairGeneratorSpi()
    {
        super("SPHINCS+");
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
        if (!(params instanceof SPHINCSPlusParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a CMCEParameterSpec");
        }
        
        param = new SPHINCSPlusKeyGenerationParameters(random, (SPHINCSPlusParameters)parameters.get(getNameFromParams(params)));

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new SPHINCSPlusKeyGenerationParameters(random, SPHINCSPlusParameters.sha256_256s);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SPHINCSPlusPublicKeyParameters pub = (SPHINCSPlusPublicKeyParameters)pair.getPublic();
        SPHINCSPlusPrivateKeyParameters priv = (SPHINCSPlusPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSPHINCSPlusPublicKey(pub), new BCSPHINCSPlusPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
        throws InvalidAlgorithmParameterException
    {
        if (paramSpec instanceof SPHINCSPlusParameterSpec)
        {
            SPHINCSPlusParameterSpec params = (SPHINCSPlusParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return SpecUtil.getNameFrom(paramSpec);
        }
    }
}
