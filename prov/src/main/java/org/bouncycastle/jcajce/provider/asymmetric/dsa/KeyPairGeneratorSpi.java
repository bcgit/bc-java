package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.util.Hashtable;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static Hashtable params = new Hashtable();
    private static Object    lock = new Object();

    DSAKeyGenerationParameters param;
    DSAKeyPairGenerator engine = new DSAKeyPairGenerator();
    int strength = 2048;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("DSA");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        if (strength < 512 || strength > 4096 || ((strength < 1024) && strength % 64 != 0) || (strength >= 1024 && strength % 1024 != 0))
        {
            throw new InvalidParameterException("strength must be from 512 - 4096 and a multiple of 1024 above 1024");
        }

        DSAParameterSpec spec = BouncyCastleProvider.CONFIGURATION.getDSADefaultParameters(strength);

        if (spec != null)
        {
            param = new DSAKeyGenerationParameters(random, new DSAParameters(spec.getP(), spec.getQ(), spec.getG()));

            engine.init(param);
            this.initialised = true;
        }
        else
        {
            this.strength = strength;
            this.random = random;
            this.initialised = false;
        }
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof DSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a DSAParameterSpec");
        }
        DSAParameterSpec dsaParams = (DSAParameterSpec)params;

        param = new DSAKeyGenerationParameters(random, new DSAParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            Integer paramStrength = Integers.valueOf(strength);

            if (params.containsKey(paramStrength))
            {
                param = (DSAKeyGenerationParameters)params.get(paramStrength);
            }
            else
            {
                synchronized (lock)
                {
                    // we do the check again in case we were blocked by a generator for
                    // our key size.
                    if (params.containsKey(paramStrength))
                    {
                        param = (DSAKeyGenerationParameters)params.get(paramStrength);
                    }
                    else
                    {
                        DSAParametersGenerator pGen;
                        DSAParameterGenerationParameters dsaParams;

                        int certainty = PrimeCertaintyCalculator.getDefaultCertainty(strength);

                        // Typical combination of keysize and size of q.
                        //     keysize = 1024, q's size = 160
                        //     keysize = 2048, q's size = 224
                        //     keysize = 2048, q's size = 256
                        //     keysize = 3072, q's size = 256
                        // For simplicity if keysize is greater than 1024 then we choose q's size to be 256.
                        // For legacy keysize that is less than 1024-bit, we just use the 186-2 style parameters
                        if (strength == 1024)
                        {
                            pGen = new DSAParametersGenerator();
                            if (Properties.isOverrideSet("org.bouncycastle.dsa.FIPS186-2for1024bits"))
                            {
                                pGen.init(strength, certainty, random);
                            }
                            else
                            {
                                dsaParams = new DSAParameterGenerationParameters(1024, 160, certainty, random);
                                pGen.init(dsaParams);
                            }
                        }
                        else if (strength > 1024)
                        {
                            dsaParams = new DSAParameterGenerationParameters(strength, 256, certainty, random);
                            pGen = new DSAParametersGenerator(new SHA256Digest());
                            pGen.init(dsaParams);
                        }
                        else
                        {
                            pGen = new DSAParametersGenerator();
                            pGen.init(strength, certainty, random);
                        }
                        param = new DSAKeyGenerationParameters(random, pGen.generateParameters());

                        params.put(paramStrength, param);
                    }
                }
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        DSAPublicKeyParameters pub = (DSAPublicKeyParameters)pair.getPublic();
        DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCDSAPublicKey(pub), new BCDSAPrivateKey(priv));
    }
}
