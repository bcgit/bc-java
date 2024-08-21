package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.util.Strings;

public class SLHDSAKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128f.getName(), SPHINCSPlusParameters.sha2_128f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128s.getName(), SPHINCSPlusParameters.sha2_128s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192f.getName(), SPHINCSPlusParameters.sha2_192f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192s.getName(), SPHINCSPlusParameters.sha2_192s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256f.getName(), SPHINCSPlusParameters.sha2_256f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256s.getName(), SPHINCSPlusParameters.sha2_256s);

        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128f.getName(), SPHINCSPlusParameters.shake_128f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(), SPHINCSPlusParameters.shake_128s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192f.getName(), SPHINCSPlusParameters.shake_192f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192s.getName(), SPHINCSPlusParameters.shake_192s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256f.getName(), SPHINCSPlusParameters.shake_256f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256s.getName(), SPHINCSPlusParameters.shake_256s);
    }

    SPHINCSPlusKeyGenerationParameters param;
    SPHINCSPlusKeyPairGenerator engine = new SPHINCSPlusKeyPairGenerator();

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public SLHDSAKeyPairGeneratorSpi()
    {
        super("SPHINCS+");
    }

    protected SLHDSAKeyPairGeneratorSpi(SLHDSAParameterSpec paramSpec)
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

        return new KeyPair(new BCSLHDSAPublicKey(pub), new BCSLHDSAPrivateKey(priv));
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof SLHDSAParameterSpec)
        {
            SLHDSAParameterSpec params = (SLHDSAParameterSpec)paramSpec;
            return params.getName();
        }
        else
        {
            return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
        }
    }

    public static class Sha2_128s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public Sha2_128s()
       {
           super(SLHDSAParameterSpec.slh_dsa_sha2_128s);
       }
    }

    public static class Sha2_128f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public Sha2_128f()
        {
            super(SLHDSAParameterSpec.slh_dsa_sha2_128f);
        }
    }

    public static class Sha2_192s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public Sha2_192s()
       {
           super(SLHDSAParameterSpec.slh_dsa_sha2_192s);
       }
    }

    public static class Sha2_192f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public Sha2_192f()
        {
            super(SLHDSAParameterSpec.slh_dsa_sha2_192f);
        }
    }

    public static class Sha2_256s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public Sha2_256s()
       {
           super(SLHDSAParameterSpec.slh_dsa_sha2_256s);
       }
    }

    public static class Sha2_256f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public Sha2_256f()
        {
            super(SLHDSAParameterSpec.slh_dsa_sha2_256f);
        }
    }
    
    public static class Shake_128s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public Shake_128s()
       {
           super(SLHDSAParameterSpec.slh_dsa_shake_128s);
       }
    }

    public static class Shake_128f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public Shake_128f()
        {
            super(SLHDSAParameterSpec.slh_dsa_shake_128f);
        }
    }

    public static class Shake_192s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public Shake_192s()
       {
           super(SLHDSAParameterSpec.slh_dsa_shake_192s);
       }
    }

    public static class Shake_192f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public Shake_192f()
        {
            super(SLHDSAParameterSpec.slh_dsa_shake_192f);
        }
    }

    public static class Shake_256s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public Shake_256s()
       {
           super(SLHDSAParameterSpec.slh_dsa_shake_256s);
       }
    }

    public static class Shake_256f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public Shake_256f()
        {
            super(SLHDSAParameterSpec.slh_dsa_shake_256f);
        }
    }
}
