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
import org.bouncycastle.util.Strings;

public class SPHINCSPlusKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(SPHINCSPlusParameterSpec.sha2_128f_robust.getName(), SPHINCSPlusParameters.sha2_128f_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_128s_robust.getName(), SPHINCSPlusParameters.sha2_128s_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192f_robust.getName(), SPHINCSPlusParameters.sha2_192f_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192s_robust.getName(), SPHINCSPlusParameters.sha2_192s_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256f_robust.getName(), SPHINCSPlusParameters.sha2_256f_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256s_robust.getName(), SPHINCSPlusParameters.sha2_256s_robust);
        
        parameters.put(SPHINCSPlusParameterSpec.sha2_128f.getName(), SPHINCSPlusParameters.sha2_128f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_128s.getName(), SPHINCSPlusParameters.sha2_128s);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192f.getName(), SPHINCSPlusParameters.sha2_192f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192s.getName(), SPHINCSPlusParameters.sha2_192s);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256f.getName(), SPHINCSPlusParameters.sha2_256f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256s.getName(), SPHINCSPlusParameters.sha2_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.shake_128f_robust.getName(), SPHINCSPlusParameters.shake_128f_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_128s_robust.getName(), SPHINCSPlusParameters.shake_128s_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_192f_robust.getName(), SPHINCSPlusParameters.shake_192f_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_192s_robust.getName(), SPHINCSPlusParameters.shake_192s_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_256f_robust.getName(), SPHINCSPlusParameters.shake_256f_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_256s_robust.getName(), SPHINCSPlusParameters.shake_256s_robust);
        
        parameters.put(SPHINCSPlusParameterSpec.shake_128f.getName(), SPHINCSPlusParameters.shake_128f);
        parameters.put(SPHINCSPlusParameterSpec.shake_128s.getName(), SPHINCSPlusParameters.shake_128s);
        parameters.put(SPHINCSPlusParameterSpec.shake_192f.getName(), SPHINCSPlusParameters.shake_192f);
        parameters.put(SPHINCSPlusParameterSpec.shake_192s.getName(), SPHINCSPlusParameters.shake_192s);
        parameters.put(SPHINCSPlusParameterSpec.shake_256f.getName(), SPHINCSPlusParameters.shake_256f);
        parameters.put(SPHINCSPlusParameterSpec.shake_256s.getName(), SPHINCSPlusParameters.shake_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.haraka_128f.getName(), SPHINCSPlusParameters.haraka_128f);
        parameters.put(SPHINCSPlusParameterSpec.haraka_128s.getName(), SPHINCSPlusParameters.haraka_128s);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192f.getName(), SPHINCSPlusParameters.haraka_192f);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192s.getName(), SPHINCSPlusParameters.haraka_192s);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256f.getName(), SPHINCSPlusParameters.haraka_256f);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256s.getName(), SPHINCSPlusParameters.haraka_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.haraka_128f_simple.getName(), SPHINCSPlusParameters.haraka_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_128s_simple.getName(), SPHINCSPlusParameters.haraka_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192f_simple.getName(), SPHINCSPlusParameters.haraka_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192s_simple.getName(), SPHINCSPlusParameters.haraka_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256f_simple.getName(), SPHINCSPlusParameters.haraka_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256s_simple.getName(), SPHINCSPlusParameters.haraka_256s_simple);
    }

    SPHINCSPlusKeyGenerationParameters param;
    SPHINCSPlusKeyPairGenerator engine = new SPHINCSPlusKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SPHINCSPlusKeyPairGeneratorSpi()
    {
        super("SPHINCS+");
    }

    protected SPHINCSPlusKeyPairGeneratorSpi(SPHINCSPlusParameterSpec paramSpec)
    {
        super("SPHINCS+" + "-" + Strings.toUpperCase(paramSpec.getName()));

        param = new SPHINCSPlusKeyGenerationParameters(random, (SPHINCSPlusParameters)parameters.get(paramSpec.getName()));

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

        if (name != null)
        {
            param = new SPHINCSPlusKeyGenerationParameters(random, (SPHINCSPlusParameters)parameters.get(name));

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
            param = new SPHINCSPlusKeyGenerationParameters(random, SPHINCSPlusParameters.sha2_256s);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SPHINCSPlusPublicKeyParameters pub = (SPHINCSPlusPublicKeyParameters)pair.getPublic();
        SPHINCSPlusPrivateKeyParameters priv = (SPHINCSPlusPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSPHINCSPlusPublicKey(pub), new BCSPHINCSPlusPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof SPHINCSPlusParameterSpec)
        {
            SPHINCSPlusParameterSpec params = (SPHINCSPlusParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class Sha2_128s
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
       public Sha2_128s()
       {
           super(SPHINCSPlusParameterSpec.sha2_128s);
       }
    }

    public static class Sha2_128f
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
        public Sha2_128f()
        {
            super(SPHINCSPlusParameterSpec.sha2_128f);
        }
    }

    public static class Sha2_192s
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
       public Sha2_192s()
       {
           super(SPHINCSPlusParameterSpec.sha2_192s);
       }
    }

    public static class Sha2_192f
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
        public Sha2_192f()
        {
            super(SPHINCSPlusParameterSpec.sha2_192f);
        }
    }

    public static class Sha2_256s
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
       public Sha2_256s()
       {
           super(SPHINCSPlusParameterSpec.sha2_256s);
       }
    }

    public static class Sha2_256f
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
        public Sha2_256f()
        {
            super(SPHINCSPlusParameterSpec.sha2_256f);
        }
    }
    
    public static class Shake_128s
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
       public Shake_128s()
       {
           super(SPHINCSPlusParameterSpec.shake_128s);
       }
    }

    public static class Shake_128f
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
        public Shake_128f()
        {
            super(SPHINCSPlusParameterSpec.shake_128f);
        }
    }

    public static class Shake_192s
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
       public Shake_192s()
       {
           super(SPHINCSPlusParameterSpec.shake_192s);
       }
    }

    public static class Shake_192f
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
        public Shake_192f()
        {
            super(SPHINCSPlusParameterSpec.shake_192f);
        }
    }

    public static class Shake_256s
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
       public Shake_256s()
       {
           super(SPHINCSPlusParameterSpec.shake_256s);
       }
    }

    public static class Shake_256f
       extends SPHINCSPlusKeyPairGeneratorSpi
    {
        public Shake_256f()
        {
            super(SPHINCSPlusParameterSpec.shake_256f);
        }
    }
}
