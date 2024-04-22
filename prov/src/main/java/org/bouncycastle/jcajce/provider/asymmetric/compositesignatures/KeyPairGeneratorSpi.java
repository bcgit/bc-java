package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;


/**
 * KeyPairGenerator class for composite signatures. Selected algorithm is set by the "subclasses" at the end of this file.
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGeneratorSpi
{
    //Enum value of the selected composite signature algorithm.
    private final CompositeSignaturesConstants.CompositeName algorithmIdentifier;
    //ASN1 OI value of the selected composite signature algorithm.
    private final ASN1ObjectIdentifier algorithmIdentifierASN1;

    //List of KeyPairGenerators. Each entry corresponds to a component signature from the composite definition.
    private List<KeyPairGenerator> generators;

    private SecureRandom secureRandom;
    private boolean parametersInitialized = false;

    KeyPairGeneratorSpi(CompositeSignaturesConstants.CompositeName algorithmIdentifier)
    {
        this.algorithmIdentifier = algorithmIdentifier;
        this.algorithmIdentifierASN1 = CompositeSignaturesConstants.compositeNameASN1IdentifierMap.get(this.algorithmIdentifier);
    }

    /**
     * Creates a list of KeyPairGenerators based on the selected composite algorithm (algorithmIdentifier).
     * Each component generator is initialized with parameters according to the specification https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html.
     * Called after initialize() method or right before keypair generation in case initialize() was not called by the user.
     */
    private void initializeParameters()
    {

        if (this.secureRandom == null)
        {
            this.secureRandom = new SecureRandom();
        }

        List<KeyPairGenerator> generators = new ArrayList<KeyPairGenerator>();
        try
        {
            switch (this.algorithmIdentifier)
            {
            case MLDSA44_Ed25519_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("Ed25519", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium2, this.secureRandom);
                generators.get(1).initialize(256, this.secureRandom);
                break;
            case MLDSA65_Ed25519_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("Ed25519", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium3, this.secureRandom);
                generators.get(1).initialize(256, this.secureRandom);
                break;
            case MLDSA87_Ed448_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("Ed448", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium5, this.secureRandom);
                generators.get(1).initialize(448, this.secureRandom);
                break;
            case MLDSA44_RSA2048_PSS_SHA256:
            case MLDSA44_RSA2048_PKCS15_SHA256:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("RSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium2, this.secureRandom);
                generators.get(1).initialize(2048, this.secureRandom);
                break;
            case MLDSA65_RSA3072_PSS_SHA512:
            case MLDSA65_RSA3072_PKCS15_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("RSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium3, this.secureRandom);
                generators.get(1).initialize(3072, this.secureRandom);
                break;
            case MLDSA44_ECDSA_P256_SHA256:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium2, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("P-256"), this.secureRandom);
                break;
            case MLDSA44_ECDSA_brainpoolP256r1_SHA256:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium2, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("brainpoolP256r1"), this.secureRandom);
                break;
            case MLDSA65_ECDSA_P256_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium3, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("P-256"), this.secureRandom);
                break;
            case MLDSA65_ECDSA_brainpoolP256r1_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium3, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("brainpoolP256r1"), this.secureRandom);
                break;
            case MLDSA87_ECDSA_P384_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium5, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("P-384"), this.secureRandom);
                break;
            case MLDSA87_ECDSA_brainpoolP384r1_SHA512:
                generators.add(KeyPairGenerator.getInstance("Dilithium", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(DilithiumParameterSpec.dilithium5, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("brainpoolP384r1"), this.secureRandom);
                break;
            case Falcon512_ECDSA_P256_SHA256:
                generators.add(KeyPairGenerator.getInstance("Falcon", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(FalconParameterSpec.falcon_512, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("P-256"), this.secureRandom);
                break;
            case Falcon512_ECDSA_brainpoolP256r1_SHA256:
                generators.add(KeyPairGenerator.getInstance("Falcon", "BC"));
                generators.add(KeyPairGenerator.getInstance("ECDSA", "BC"));
                generators.get(0).initialize(FalconParameterSpec.falcon_512, this.secureRandom);
                generators.get(1).initialize(new ECGenParameterSpec("brainpoolP256r1"), this.secureRandom);
                break;
            case Falcon512_Ed25519_SHA512:
                generators.add(KeyPairGenerator.getInstance("Falcon", "BC"));
                generators.add(KeyPairGenerator.getInstance("Ed25519", "BC"));
                generators.get(0).initialize(FalconParameterSpec.falcon_512, this.secureRandom);
                generators.get(1).initialize(256, this.secureRandom);
                break;
            default:
                throw new IllegalStateException("Generators not correctly initialized. Unsupported composite algorithm.");
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new RuntimeException(e);
        }

        this.generators = Collections.unmodifiableList(generators);
        this.parametersInitialized = true;
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

        this.secureRandom = secureRandom;
        initializeParameters();
    }

    public KeyPair generateKeyPair()
    {
        if (!this.parametersInitialized)
        {
            this.initializeParameters();
        }

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
        PublicKey[] publicKeys = new PublicKey[generators.size()];
        PrivateKey[] privateKeys = new PrivateKey[generators.size()];
        for (int i = 0; i < generators.size(); i++)
        {
            KeyPair keyPair = generators.get(i).generateKeyPair();
            publicKeys[i] = keyPair.getPublic();
            privateKeys[i] = keyPair.getPrivate();
        }
        CompositePublicKey compositePublicKey = new CompositePublicKey(this.algorithmIdentifierASN1, publicKeys);
        CompositePrivateKey compositePrivateKey = new CompositePrivateKey(this.algorithmIdentifierASN1, privateKeys);
        return new KeyPair(compositePublicKey, compositePrivateKey);
    }

    public static final class MLDSA44_Ed25519_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_Ed25519_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_Ed25519_SHA512);
        }
    }

    public static final class MLDSA65_Ed25519_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_Ed25519_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_Ed25519_SHA512);
        }
    }

    public static final class MLDSA87_Ed448_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_Ed448_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_Ed448_SHA512);
        }
    }

    public static final class MLDSA44_RSA2048_PSS_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_RSA2048_PSS_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    public static final class MLDSA44_RSA2048_PKCS15_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    public static final class MLDSA65_RSA3072_PSS_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA3072_PSS_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    public static final class MLDSA65_RSA3072_PKCS15_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_RSA3072_PKCS15_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    public static final class MLDSA44_ECDSA_P256_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_ECDSA_P256_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_P256_SHA256);
        }
    }

    public static final class MLDSA44_ECDSA_brainpoolP256r1_SHA256
        extends KeyPairGeneratorSpi
    {
        public MLDSA44_ECDSA_brainpoolP256r1_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    public static final class MLDSA65_ECDSA_P256_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_ECDSA_P256_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_P256_SHA512);
        }
    }

    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        }
    }

    public static final class MLDSA87_ECDSA_P384_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_ECDSA_P384_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_P384_SHA512);
        }
    }

    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA512
        extends KeyPairGeneratorSpi
    {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        }
    }

    public static final class Falcon512_Ed25519_SHA512
        extends KeyPairGeneratorSpi
    {
        public Falcon512_Ed25519_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_Ed25519_SHA512);
        }
    }

    public static final class Falcon512_ECDSA_P256_SHA256
        extends KeyPairGeneratorSpi
    {
        public Falcon512_ECDSA_P256_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_P256_SHA256);
        }
    }

    public static final class Falcon512_ECDSA_brainpoolP256r1_SHA256
        extends KeyPairGeneratorSpi
    {
        public Falcon512_ECDSA_brainpoolP256r1_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256);
        }
    }


}
