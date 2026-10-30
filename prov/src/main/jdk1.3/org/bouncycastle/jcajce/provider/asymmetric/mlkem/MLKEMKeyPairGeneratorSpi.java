package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

// NOTE: jdk1.3 overlay. On JRE 1.3 JcaJceHelper.createSecureRandom uses
// SecureRandom.getInstance(alg, providerName), which also throws NoSuchProviderException;
// base catches only NoSuchAlgorithmException. Overlay adds the extra catch (base cannot,
// as the exception is unreachable on modern JDKs). Keep in lockstep with base otherwise.

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

/**
 * ML-KEM (FIPS 203) key pair generation. A generator obtained as "ML-KEM" and not initialised
 * produces ML-KEM-768 keys, the parameter set NIST recommends (NIST IR 8547). An initialisation
 * that gives no SecureRandom, including this default and a generator obtained under a parameter set
 * name such as "ML-KEM-512", draws the key from the
 * default SecureRandom set on CryptoServicesRegistrar, if one has been set, and otherwise from the provider's
 * 256 bit DEFAULT DRBG.
 */
public class MLKEMKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    MLKEMKeyGenerationParameters param;
    MLKEMKeyPairGenerator engine = new MLKEMKeyPairGenerator();

    boolean initialised = false;
    private MLKEMParameters mlkemParameters;

    public MLKEMKeyPairGeneratorSpi()
    {
        super("ML-KEM");
    }

    protected MLKEMKeyPairGeneratorSpi(MLKEMParameterSpec paramSpec)
    {
        super(Strings.toUpperCase(paramSpec.getName()));
        this.mlkemParameters = Utils.getParameters(paramSpec.getName());
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
            MLKEMParameters mlkemParams = Utils.getParameters(name);
            if (mlkemParams == null)
            {
                throw new InvalidAlgorithmParameterException("unknown parameter set name: " + name);
            }

            if (mlkemParameters != null && !mlkemParams.getName().equals(mlkemParameters.getName()))
            {
                throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
            }

            param = new MLKEMKeyGenerationParameters(random, (MLKEMParameters)mlkemParams);

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
            if (mlkemParameters != null)
            {
                // locked to a parameter set: set up on first use, so a generator given its own SecureRandom never builds a DRBG
                param = new MLKEMKeyGenerationParameters(createDefaultRandom(), mlkemParameters);
                engine.init(param);
                initialised = true;
            }
            else
            {
                // NIST's recommended default set (NIST IR 8547), drawn from the DEFAULT DRBG as initialize() does
                try
                {
                    initialize(MLKEMParameterSpec.ml_kem_768);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw Exceptions.illegalStateException("unable to apply the default parameter set", e);
                }
            }
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters)pair.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCMLKEMPublicKey(pub), new BCMLKEMPrivateKey(priv));
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
        catch (NoSuchProviderException e)
        {
            throw Exceptions.illegalStateException("unable to find DEFAULT DRBG", e);
        }
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
            String name = SpecUtil.getNameFrom(paramSpec);

            // null where the spec has no getName(), which the caller reports as the exception it declares
            return (name == null) ? null : Strings.toUpperCase(name);
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
