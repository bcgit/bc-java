package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Integers;

public abstract class GMKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    public GMKeyPairGeneratorSpi(String algorithmName)
    {
        super(algorithmName);
    }

    public static class BaseSM2
        extends GMKeyPairGeneratorSpi
    {
        ECKeyGenerationParameters   param;
        ECKeyPairGenerator          engine = new ECKeyPairGenerator();
        Object                      ecParams = null;
        int                         strength = 239;
        SecureRandom                random = CryptoServicesRegistrar.getSecureRandom();
        boolean                     initialised = false;
        String                      algorithm;
        ProviderConfiguration       configuration;

        static private Hashtable    ecParameters;

        static
        {
            ecParameters = new Hashtable();

            ecParameters.put(Integers.valueOf(192), new ECNamedCurveGenParameterSpec("prime192v1")); // a.k.a P-192
            ecParameters.put(Integers.valueOf(239), new ECNamedCurveGenParameterSpec("prime239v1"));
            ecParameters.put(Integers.valueOf(256), new ECNamedCurveGenParameterSpec("prime256v1")); // a.k.a P-256

            ecParameters.put(Integers.valueOf(224), new ECNamedCurveGenParameterSpec("P-224"));
            ecParameters.put(Integers.valueOf(384), new ECNamedCurveGenParameterSpec("P-384"));
            ecParameters.put(Integers.valueOf(521), new ECNamedCurveGenParameterSpec("P-521"));
        }

        public BaseSM2()
        {
            super("EC");
            this.algorithm = "EC";
            this.configuration = BouncyCastleProvider.CONFIGURATION;
        }

        public BaseSM2(
            String  algorithm,
            ProviderConfiguration configuration)
        {
            super(algorithm);
            this.algorithm = algorithm;
            this.configuration = configuration;
        }

        public void initialize(
            int             strength,
            SecureRandom    random)
        {
            this.strength = strength;
            this.random = random;

            ECNamedCurveGenParameterSpec ecParams = (ECNamedCurveGenParameterSpec)ecParameters.get(Integers.valueOf(strength));
            if (ecParams == null)
            {
                throw new InvalidParameterException("unknown key size.");
            }

            try
            {
                initialize(ecParams, random);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new InvalidParameterException("key size not configurable.");
            }
        }

        public void initialize(
            AlgorithmParameterSpec  params,
            SecureRandom            random)
            throws InvalidAlgorithmParameterException
        {
            if (params == null)
            {
                ECParameterSpec implicitCA = configuration.getEcImplicitlyCa();
                if (implicitCA == null)
                {
                    throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
                }

                this.ecParams = null;
                this.param = createKeyGenParamsBC(implicitCA, random);
            }
            else if (params instanceof ECParameterSpec)
            {
                this.ecParams = params;
                this.param = createKeyGenParamsBC((ECParameterSpec)params, random);
            }
            else if (params instanceof ECNamedCurveGenParameterSpec)
            {
                initializeNamedCurve(((ECNamedCurveGenParameterSpec)params).getName(), random);
            }
            else
            {
                throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + params);
            }

            engine.init(param);
            initialised = true;
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                initialize(strength, new SecureRandom());
            }

            AsymmetricCipherKeyPair     pair = engine.generateKeyPair();
            ECPublicKeyParameters       pub = (ECPublicKeyParameters)pair.getPublic();
            ECPrivateKeyParameters      priv = (ECPrivateKeyParameters)pair.getPrivate();

            if (ecParams instanceof ECParameterSpec)
            {
                ECParameterSpec p = (ECParameterSpec)ecParams;

                BCECPublicKey pubKey = new BCECPublicKey(algorithm, pub, p, configuration);
                return new KeyPair(pubKey,
                                   new BCECPrivateKey(algorithm, priv, pubKey, p, configuration));
            }
            else
            {
               return new KeyPair(new BCECPublicKey(algorithm, pub, configuration),
                                   new BCECPrivateKey(algorithm, priv, configuration));
            }
        }

        protected ECKeyGenerationParameters createKeyGenParamsBC(ECParameterSpec p, SecureRandom r)
        {
            return new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), r);
        }

        protected ECKeyGenerationParameters createKeyGenParamsJCE(X9ECParameters x9, SecureRandom r)
        {
            ECDomainParameters dp = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

            return new ECKeyGenerationParameters(dp, r);
        }

        protected void initializeNamedCurve(String curveName, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            X9ECParameters x9 = ECUtils.getDomainParametersFromName(curveName, configuration);
            if (null == x9)
            {
                throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
            }

            // Work-around for JDK bug -- it won't look up named curves properly if seed is present
            byte[] seed = null; //p.getSeed();


            this.ecParams = new ECNamedCurveParameterSpec(curveName, x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), seed);
            createKeyGenParamsBC((ECParameterSpec)ecParams, random);
        }
    }

    public static class SM2
        extends BaseSM2
    {
        public SM2()
        {
            super("SM2", BouncyCastleProvider.CONFIGURATION);
        }
    }
}
