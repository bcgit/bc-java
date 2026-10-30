package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/**
 * {@link javax.crypto.KEM} support for Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), registered
 * under each composite algorithm name and OID (for example {@code KEM.MLKEM768-X25519-SHA3-256}). The
 * keys are the {@link CompositePublicKey} / {@link CompositePrivateKey} pairs of the composite
 * KeyPairGenerator and KeyFactory, and must be of the parameter set the service was obtained for.
 * <p>
 * With a null spec the shared secret is the 32-byte output of the draft's SHA3-256 combiner - the
 * interoperable form, and the one the CMS KEMRecipientInfo use expects. A {@link KTSParameterSpec}
 * KDF may optionally be layered on top.
 */
public class CompositeKEMSpi
    implements KEMSpi
{
    private final ASN1ObjectIdentifier compositeOID;
    private final String algorithmName;

    protected CompositeKEMSpi(ASN1ObjectIdentifier compositeOID)
    {
        this.compositeOID = compositeOID;
        this.algorithmName = CompositeIndex.getAlgorithmName(compositeOID);
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof CompositePublicKey compositeKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }
        if (!compositeOID.equals(compositeKey.getAlgorithmIdentifier().getAlgorithm()))
        {
            throw new InvalidKeyException("key is not a " + algorithmName + " key");
        }

        return new CompositeKEMEncapsulatorSpi(compositeOID, compositeKey, resolveSpec(spec), secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof CompositePrivateKey compositeKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }
        if (!compositeOID.equals(compositeKey.getAlgorithmIdentifier().getAlgorithm()))
        {
            throw new InvalidKeyException("key is not a " + algorithmName + " key");
        }

        return new CompositeKEMDecapsulatorSpi(compositeOID, compositeKey, resolveSpec(spec));
    }

    private KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException
    {
        // the combiner is SHA3-256 for every composite ML-KEM parameter set, so the shared secret is 256 bits
        return KdfUtil.resolveKemSpec(spec, algorithmName, algorithmName, 256);
    }

    public static class MLKEM768_RSA2048_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM768_RSA2048_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256);
        }
    }

    public static class MLKEM768_RSA3072_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM768_RSA3072_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256);
        }
    }

    public static class MLKEM768_RSA4096_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM768_RSA4096_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256);
        }
    }

    public static class MLKEM768_X25519_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM768_X25519_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256);
        }
    }

    public static class MLKEM768_ECDH_P256_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM768_ECDH_P256_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256);
        }
    }

    public static class MLKEM768_ECDH_P384_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM768_ECDH_P384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256);
        }
    }

    public static class MLKEM768_ECDH_brainpoolP256r1_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM768_ECDH_brainpoolP256r1_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256);
        }
    }

    public static class MLKEM1024_RSA3072_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM1024_RSA3072_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256);
        }
    }

    public static class MLKEM1024_ECDH_P384_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM1024_ECDH_P384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256);
        }
    }

    public static class MLKEM1024_ECDH_brainpoolP384r1_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM1024_ECDH_brainpoolP384r1_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256);
        }
    }

    public static class MLKEM1024_X448_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM1024_X448_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256);
        }
    }

    public static class MLKEM1024_ECDH_P521_SHA3_256
        extends CompositeKEMSpi
    {
        public MLKEM1024_ECDH_P521_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256);
        }
    }
}
