package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.util.Strings;

/**
 * SLH-DSA (FIPS 205) key pair generation. A generator obtained as "SLH-DSA" and not initialised
 * produces SLH-DSA-SHA2-128F keys ("HASH-SLH-DSA" SLH-DSA-SHA2-128F-WITH-SHA256). An initialisation
 * that gives no SecureRandom, including this default and a generator obtained under a parameter set
 * name, draws the key from the
 * default SecureRandom set on CryptoServicesRegistrar, if one has been set, and otherwise from the provider's
 * 256 bit DEFAULT DRBG.
 */
public class SLHDSAKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128f.getName(), SLHDSAParameters.sha2_128f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128s.getName(), SLHDSAParameters.sha2_128s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192f.getName(), SLHDSAParameters.sha2_192f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192s.getName(), SLHDSAParameters.sha2_192s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256f.getName(), SLHDSAParameters.sha2_256f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256s.getName(), SLHDSAParameters.sha2_256s);

        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128f.getName(), SLHDSAParameters.shake_128f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(), SLHDSAParameters.shake_128s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192f.getName(), SLHDSAParameters.shake_192f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192s.getName(), SLHDSAParameters.shake_192s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256f.getName(), SLHDSAParameters.shake_256f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256s.getName(), SLHDSAParameters.shake_256s);
        
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256.getName(), SLHDSAParameters.sha2_128f_with_sha256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256.getName(), SLHDSAParameters.sha2_128s_with_sha256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512.getName(), SLHDSAParameters.sha2_192f_with_sha512);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512.getName(), SLHDSAParameters.sha2_192s_with_sha512);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512.getName(), SLHDSAParameters.sha2_256f_with_sha512);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512.getName(), SLHDSAParameters.sha2_256s_with_sha512);

        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128.getName(), SLHDSAParameters.shake_128f_with_shake128);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128.getName(), SLHDSAParameters.shake_128s_with_shake128);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256.getName(), SLHDSAParameters.shake_192f_with_shake256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256.getName(), SLHDSAParameters.shake_192s_with_shake256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256.getName(), SLHDSAParameters.shake_256f_with_shake256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256.getName(), SLHDSAParameters.shake_256s_with_shake256);
    }

    SLHDSAKeyGenerationParameters param;
    SLHDSAKeyPairGenerator engine = new SLHDSAKeyPairGenerator();

    boolean initialised = false;
    private SLHDSAParameters slhdsaParameters;

    public SLHDSAKeyPairGeneratorSpi(String name)
    {
        super(name);
    }

    protected SLHDSAKeyPairGeneratorSpi(SLHDSAParameterSpec paramSpec)
    {
        super(Strings.toUpperCase(paramSpec.getName()));

        this.slhdsaParameters = (SLHDSAParameters)parameters.get(paramSpec.getName());
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        // what the JCA specifies here; it extends IllegalArgumentException, so catches still match
        throw new InvalidParameterException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        initialize(params, createDefaultRandom());
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);

        if (name != null)
        {
            SLHDSAParameters parameters = (SLHDSAParameters)SLHDSAKeyPairGeneratorSpi.parameters.get(name);
            if (parameters == null)
            {
                throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
            }

            if (slhdsaParameters != null && !parameters.getName().equals(slhdsaParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
            }

            param = new SLHDSAKeyGenerationParameters(random, parameters);

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
            if (slhdsaParameters != null)
            {
                // locked to a parameter set: set up on first use, so a generator given its own SecureRandom never builds a DRBG
                param = new SLHDSAKeyGenerationParameters(createDefaultRandom(), slhdsaParameters);
                engine.init(param);
                initialised = true;
            }
            else
            {
                // drawn from the DEFAULT DRBG, as initialize() without a SecureRandom does
                try
                {
                    if (this.getAlgorithm().startsWith("HASH"))
                    {
                        initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256);
                    }
                    else
                    {
                        initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f);
                    }
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw Exceptions.illegalStateException("unable to apply the default parameter set", e);
                }
            }
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SLHDSAPublicKeyParameters pub = (SLHDSAPublicKeyParameters)pair.getPublic();
        SLHDSAPrivateKeyParameters priv = (SLHDSAPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSLHDSAPublicKey(pub), new BCSLHDSAPrivateKey(priv));
    }

    // used wherever the caller supplies no SecureRandom: one set on CryptoServicesRegistrar, otherwise the provider's 256 bit DEFAULT DRBG
    private static SecureRandom createDefaultRandom()
    {
        if (CryptoServicesRegistrar.isSecureRandomSpecified())
        {
            return CryptoServicesRegistrar.getSecureRandom();
        }

        try
        {
            return new BCJcaJceHelper().createSecureRandom("DEFAULT");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw Exceptions.illegalStateException("unable to find DEFAULT DRBG", e);
        }
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
            String name = SpecUtil.getNameFrom(paramSpec);

            // null where the spec has no getName(), which the caller reports as the exception it declares
            return (name == null) ? null : Strings.toUpperCase(name);
        }
    }

    public static class Pure
        extends SLHDSAKeyPairGeneratorSpi
    {
        public Pure()
            throws NoSuchAlgorithmException
        {
            super("SLH-DSA");
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

    public static class Hash
        extends SLHDSAKeyPairGeneratorSpi
    {
        public Hash()
            throws NoSuchAlgorithmException
        {
            super("HASH-SLH-DSA");
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
    
    public static class HashSha2_128s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public HashSha2_128s()
       {
           super(SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256);
       }
    }

    public static class HashSha2_128f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public HashSha2_128f()
        {
            super(SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256);
        }
    }

    public static class HashSha2_192s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public HashSha2_192s()
       {
           super(SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512);
       }
    }

    public static class HashSha2_192f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public HashSha2_192f()
        {
            super(SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512);
        }
    }

    public static class HashSha2_256s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public HashSha2_256s()
       {
           super(SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512);
       }
    }

    public static class HashSha2_256f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public HashSha2_256f()
        {
            super(SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512);
        }
    }
    
    public static class HashShake_128s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public HashShake_128s()
       {
           super(SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128);
       }
    }

    public static class HashShake_128f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public HashShake_128f()
        {
            super(SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128);
        }
    }

    public static class HashShake_192s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public HashShake_192s()
       {
           super(SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256);
       }
    }

    public static class HashShake_192f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public HashShake_192f()
        {
            super(SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256);
        }
    }

    public static class HashShake_256s
       extends SLHDSAKeyPairGeneratorSpi
    {
       public HashShake_256s()
       {
           super(SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256);
       }
    }

    public static class HashShake_256f
       extends SLHDSAKeyPairGeneratorSpi
    {
        public HashShake_256f()
        {
            super(SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256);
        }
    }
}
