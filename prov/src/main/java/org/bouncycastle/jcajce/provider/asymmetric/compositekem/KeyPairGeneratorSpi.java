package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.util.Exceptions;

/**
 * KeyPairGenerator for Composite ML-KEM (draft-ietf-lamps-pq-composite-kem). The concrete composite
 * is selected by the subclasses at the end of this file. The generated keys are a
 * {@link CompositePublicKey} / {@link CompositePrivateKey} pair whose components are, in order, the
 * ML-KEM key and the traditional (RSA / ECDH / X25519 / X448) key.
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGeneratorSpi
{
    private final ASN1ObjectIdentifier algorithm;
    private final KeyPairGenerator[] generators;

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
                throw Exceptions.illegalStateException("unable to create base generator: " + e.getMessage(), e);
            }
        }
    }

    /**
     * There is no notion of a key size for composite KEMs - the parameter set is fixed by the
     * algorithm. Use {@link #initialize(AlgorithmParameterSpec, SecureRandom)} (with a null spec)
     * only to supply a custom SecureRandom.
     */
    public void initialize(int keySize, SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    /**
     * A custom AlgorithmParameterSpec is not supported - the composite parameter set is determined
     * by the algorithm name. This method only serves to set a custom SecureRandom on the component
     * generators.
     *
     * @param paramSpec    must be null.
     * @param secureRandom a SecureRandom used by the component key generators.
     */
    public void initialize(AlgorithmParameterSpec paramSpec, SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException
    {
        if (paramSpec != null)
        {
            throw new IllegalArgumentException("use initialize only for custom SecureRandom; AlgorithmParameterSpec must be null because it is determined by the algorithm name");
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

    public static final class MLKEM768_RSA2048_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM768_RSA2048_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256);
        }
    }

    public static final class MLKEM768_RSA3072_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM768_RSA3072_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256);
        }
    }

    public static final class MLKEM768_RSA4096_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM768_RSA4096_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256);
        }
    }

    public static final class MLKEM768_X25519_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM768_X25519_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256);
        }
    }

    public static final class MLKEM768_ECDH_P256_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM768_ECDH_P256_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256);
        }
    }

    public static final class MLKEM768_ECDH_P384_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM768_ECDH_P384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256);
        }
    }

    public static final class MLKEM768_ECDH_BP256_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM768_ECDH_BP256_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256);
        }
    }

    public static final class MLKEM1024_RSA3072_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM1024_RSA3072_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256);
        }
    }

    public static final class MLKEM1024_ECDH_P384_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM1024_ECDH_P384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256);
        }
    }

    public static final class MLKEM1024_ECDH_BP384_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM1024_ECDH_BP384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256);
        }
    }

    public static final class MLKEM1024_X448_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM1024_X448_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256);
        }
    }

    public static final class MLKEM1024_ECDH_P521_SHA3_256
        extends KeyPairGeneratorSpi
    {
        public MLKEM1024_ECDH_P521_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256);
        }
    }
}
