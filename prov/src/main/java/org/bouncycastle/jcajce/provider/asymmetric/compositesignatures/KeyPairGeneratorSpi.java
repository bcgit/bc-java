package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;


/**
 * KeyPairGenerator class for composite signatures. Selected algorithm is set by the "subclasses" at the end of this file.
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGeneratorSpi
{
    private final ASN1ObjectIdentifier algorithm;
    private final KeyPairGenerator[] generators;

    private SecureRandom secureRandom;
    private boolean parametersInitialized = false;

    KeyPairGeneratorSpi(ASN1ObjectIdentifier algorithm)
    {
        this.algorithm = algorithm;

        String[] algorithms = CompositeIndex.getPairing(algorithm);
        AlgorithmParameterSpec[] initSpecs = CompositeIndex.getKeyPairSpecs(algorithm);

        this.generators = new KeyPairGenerator[algorithms.length];
        for (int i = 0; i != algorithms.length; i++)
        {
            try
            {
                this.generators[i] = KeyPairGenerator.getInstance(CompositeIndex.getBaseName(algorithms[i]), "BC");


                AlgorithmParameterSpec initSpec = initSpecs[i];
                if (initSpec != null)
                {
                    this.generators[i].initialize(initSpec);
                }
            }
            catch (Exception e)
            {
                throw new IllegalStateException("unable to create base generator: " + e.getMessage());
            }
        }
    }

    /**
     * Native public method. There is no notion of a keysize for composite signatures. Therefore, this method is
     * unsupported. For setting a custom SecureRandom the other initialize method must be used.
     *
     * @param keySize
     * @param random
     */
    @Override
    public void initialize(int keySize, SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    /**
     * Setting custom AlgorithmParameterSpec is not supported since the composite signature algorithm definition
     * allow only for one specific parameter spec which is initialized by the initializeParameters method.
     * This method only serves to set a custom SecureRandom.
     *
     * @param paramSpec    Unsupported, needs to be null.
     * @param secureRandom A SecureRandom used by component key generators.
     * @throws InvalidAlgorithmParameterException
     */
    public void initialize(AlgorithmParameterSpec paramSpec, SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException
    {
        if (paramSpec != null)
        {
            throw new IllegalArgumentException("Use initialize only for custom SecureRandom. AlgorithmParameterSpec must be null because it is determined by algorithm name.");
        }

        AlgorithmParameterSpec[] initSpecs = CompositeIndex.getKeyPairSpecs(algorithm);
        for (int i = 0; i != initSpecs.length; i++)
        {
            AlgorithmParameterSpec initSpec = initSpecs[i];
            if (initSpec != null)
            {
                this.generators[i].initialize(initSpec, secureRandom);
            }
        }
    }

    public KeyPair generateKeyPair()
    {
        return getCompositeKeyPair();
    }

    /**
     * Generates a KeyPair of CompositePublicKey and CompositePrivateKey.
     * It iterates over the generators list which was created based on the composite signature type.
     *
     * @return A composite KeyPair
     */
    private KeyPair getCompositeKeyPair()
    {
        PublicKey[] publicKeys = new PublicKey[generators.length];
        PrivateKey[] privateKeys = new PrivateKey[generators.length];
        for (int i = 0; i < generators.length; i++)
        {
            KeyPair keyPair = generators[i].generateKeyPair();
            publicKeys[i] = keyPair.getPublic();
            privateKeys[i] = keyPair.getPrivate();
        }
        CompositePublicKey compositePublicKey = new CompositePublicKey(this.algorithm, publicKeys);
        CompositePrivateKey compositePrivateKey = new CompositePrivateKey(this.algorithm, privateKeys);
        return new KeyPair(compositePublicKey, compositePrivateKey);
    }

    public static final class HashMLDSA44_ECDSA_P256_SHA256
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA44_ECDSA_P256_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256);
        }
    }

    public static final class HashMLDSA44_Ed25519_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA44_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512);
        }
    }

    public static final class HashMLDSA44_RSA2048_PKCS15_SHA256
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    public static final class HashMLDSA44_RSA2048_PSS_SHA256
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA44_RSA2048_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256);
        }
    }

    public static final class HashMLDSA65_ECDSA_brainpoolP256r1_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA65_ECDSA_brainpoolP256r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512);
        }
    }

    public static final class HashMLDSA65_ECDSA_P384_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA65_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512);
        }
    }

    public static final class HashMLDSA65_Ed25519_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA65_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512);
        }
    }

    public static final class HashMLDSA65_RSA3072_PKCS15_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA65_RSA3072_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    public static final class HashMLDSA65_RSA3072_PSS_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA65_RSA3072_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512);
        }
    }

    public static final class HashMLDSA65_RSA4096_PKCS15_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA65_RSA4096_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512);
        }
    }

    public static final class HashMLDSA65_RSA4096_PSS_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA65_RSA4096_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512);
        }
    }

    public static final class HashMLDSA87_ECDSA_brainpoolP384r1_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA87_ECDSA_brainpoolP384r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512);
        }
    }

    public static final class HashMLDSA87_ECDSA_P384_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA87_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512);
        }
    }

    public static final class HashMLDSA87_Ed448_SHA512
        extends KeyPairGeneratorSpi
    {
        public HashMLDSA87_Ed448_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512);
        }
    }

    public static final class MLDSA44_ECDSA_P256_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_ECDSA_P256_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        }
    }

    public static final class MLDSA44_Ed25519_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        }
    }

    public static final class MLDSA44_RSA2048_PKCS15_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    public static final class MLDSA44_RSA2048_PSS_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_RSA2048_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    public static final class MLDSA65_ECDSA_P384_SHA384
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_ECDSA_P384_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384);
        }
    }

    public static final class MLDSA65_Ed25519_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        }
    }

    public static final class MLDSA65_RSA3072_PKCS15_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA3072_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256);
        }
    }

    public static final class MLDSA65_RSA3072_PSS_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA3072_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256);
        }
    }

    public static final class MLDSA65_RSA4096_PKCS15_SHA384
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA4096_PKCS15_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384);
        }
    }

    public static final class MLDSA65_RSA4096_PSS_SHA384
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA4096_PSS_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384);
        }
    }

    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA384
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384);
        }
    }

    public static final class MLDSA87_ECDSA_P384_SHA384
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_ECDSA_P384_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384);
        }
    }

    public static final class MLDSA87_Ed448_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_Ed448_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512);
        }
    }

    public static final class MLDSA65_RSA3072_PSS_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA3072_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    public static final class MLDSA65_RSA3072_PKCS15_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA3072_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    public static final class MLDSA65_RSA4096_PSS_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA4096_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512);
        }
    }

    public static final class MLDSA65_RSA4096_PKCS15_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA4096_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512);
        }
    }

    public static final class MLDSA65_ECDSA_P256_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_ECDSA_P256_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512);
        }
    }

    public static final class MLDSA65_ECDSA_P384_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512);
        }
    }

    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        }
    }

    public static final class MLDSA87_ECDSA_P384_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512);
        }
    }

    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        }
    }

    public static final class MLDSA87_Ed448_SHAKE256
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_Ed448_SHAKE256()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256);
        }
    }

    public static final class MLDSA87_RSA4096_PSS_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_RSA4096_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512);
        }
    }

    public static final class MLDSA87_ECDSA_P521_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_ECDSA_P521_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512);
        }
    }

    public static final class MLDSA87_RSA3072_PSS_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_RSA3072_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512);
        }
    }

}
