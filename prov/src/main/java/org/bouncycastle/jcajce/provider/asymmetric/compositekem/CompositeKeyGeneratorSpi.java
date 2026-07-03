package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMKDFSpec;

/**
 * JCE KeyGenerator SPI for Composite ML-KEM as defined in the IETF LAMPS draft:
 * <a href="https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem">
 *     Composite ML-KEM for use in X.509 Public Key Infrastructure</a>
 */
public class CompositeKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private final ASN1ObjectIdentifier fixedOid;  // if locked to a specific composite OID

    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

    protected CompositeKeyGeneratorSpi(ASN1ObjectIdentifier fixedOid)
    {
        this.fixedOid = fixedOid;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported; use KEMGenerateSpec or KEMExtractSpec");
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        this.random = random;
        ASN1ObjectIdentifier keyOid;
        if (params instanceof KEMGenerateSpec)
        {
            this.genSpec = (KEMGenerateSpec)params;
            this.extSpec = null;

            if (!(genSpec.getPublicKey() instanceof CompositePublicKey))
            {
                throw new InvalidAlgorithmParameterException("Public key must be a CompositePublicKey");
            }
            CompositePublicKey pubKey = (CompositePublicKey)genSpec.getPublicKey();
            keyOid = pubKey.getAlgorithmIdentifier().getAlgorithm();
        }
        else if (params instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec)params;

            if (!(extSpec.getPrivateKey() instanceof CompositePrivateKey))
            {
                throw new InvalidAlgorithmParameterException("Private key must be a CompositePrivateKey");
            }
            CompositePrivateKey privKey = (CompositePrivateKey)extSpec.getPrivateKey();
            keyOid = privKey.getAlgorithmIdentifier().getAlgorithm();
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Unknown spec: " + params.getClass().getName());
        }

        if (fixedOid != null && !fixedOid.equals(keyOid))
        {
            throw new InvalidAlgorithmParameterException("Key generator locked to " + fixedOid + ", but key uses " + keyOid);
        }
    }

    @Override
    protected void engineInit(int keySize, SecureRandom random)
    {
        throw new UnsupportedOperationException("Operation not supported; use KEMGenerateSpec or KEMExtractSpec");
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        byte[] encapsulation;
        String algorithm;
        KEMKDFSpec spec;
        byte[] kemSecret;
        CompositeMLKEMEngine engine = new CompositeMLKEMEngine(fixedOid, random);
        if (genSpec != null)
        {
            // --- Encapsulation (sender side) ---
            spec = genSpec;
            CompositePublicKey pubKey = (CompositePublicKey)genSpec.getPublicKey();
            algorithm = genSpec.getKeyAlgorithmName();
            try
            {

                SecretWithEncapsulation secEnc = engine.encapsulate(pubKey);
                kemSecret = secEnc.getSecret();
                encapsulation = secEnc.getEncapsulation();
            }
            catch (Exception e)
            {
                throw new IllegalStateException("Encapsulation failed: " + e.getMessage(), e);
            }
        }
        else
        {
            // --- Decapsulation (receiver side) ---
            spec = extSpec;
            CompositePrivateKey privKey = (CompositePrivateKey)extSpec.getPrivateKey();
            encapsulation = extSpec.getEncapsulation();
            algorithm = extSpec.getKeyAlgorithmName();
            try
            {
                kemSecret = engine.decapsulate(privKey, encapsulation);
            }
            catch (Exception e)
            {
                throw new IllegalStateException("Decapsulation failed: " + e.getMessage(), e);
            }
        }
        SecretKeySpec secretKey = new SecretKeySpec(KdfUtil.makeKeyBytes(spec, kemSecret), algorithm);
        // TODO Why do we return ...WithEncapsulation for Decapsulation??
        return new SecretKeyWithEncapsulation(secretKey, encapsulation);
    }

    // --- Inner classes for each specific composite algorithm (optional) ---
    // These lock the generator to a particular OID.

    public static class MLKEM768_RSA2048_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM768_RSA2048_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256);
        }
    }

    public static class MLKEM768_RSA3072_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM768_RSA3072_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256);
        }
    }

    public static class MLKEM768_RSA4096_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM768_RSA4096_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256);
        }
    }

    public static class MLKEM768_X25519_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM768_X25519_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256);
        }
    }

    public static class MLKEM768_ECDH_P256_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM768_ECDH_P256_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256);
        }
    }

    public static class MLKEM768_ECDH_P384_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM768_ECDH_P384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256);
        }
    }

    public static class MLKEM768_ECDH_BP256_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM768_ECDH_BP256_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256);
        }
    }

    public static class MLKEM1024_RSA3072_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM1024_RSA3072_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256);
        }
    }

    public static class MLKEM1024_ECDH_P384_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM1024_ECDH_P384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256);
        }
    }

    public static class MLKEM1024_ECDH_BP384_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM1024_ECDH_BP384_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256);
        }
    }

    public static class MLKEM1024_X448_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM1024_X448_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256);
        }
    }

    public static class MLKEM1024_ECDH_P521_SHA3_256
        extends CompositeKeyGeneratorSpi
    {
        public MLKEM1024_ECDH_P521_SHA3_256()
        {
            super(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256);
        }
    }
}