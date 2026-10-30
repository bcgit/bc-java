package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

public class JcaPGPKeyPairGeneratorProvider
    extends PGPKeyPairGeneratorProvider
{

    private OperatorHelper helper;
    private SecureRandom secureRandom = CryptoServicesRegistrar.getSecureRandom();

    public JcaPGPKeyPairGeneratorProvider()
    {
        this.helper = OperatorUtils.createDefaultHelper();
    }


    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider provider object for cryptographic primitives.
     * @return the current builder.
     */
    public JcaPGPKeyPairGeneratorProvider setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);
        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName the name of the provider to reference for cryptographic primitives.
     * @return the current builder.
     */
    public JcaPGPKeyPairGeneratorProvider setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);
        return this;
    }

    public JcaPGPKeyPairGeneratorProvider setSecureRandom(SecureRandom random)
    {
        this.secureRandom = random;
        return this;
    }


    @Override
    public PGPKeyPairGenerator get(int version, Date creationTime)
    {
        return new JcaPGPKeyPairGenerator(version, creationTime, helper, secureRandom);
    }

    private static class JcaPGPKeyPairGenerator
        extends PGPKeyPairGenerator
    {

        private final OperatorHelper helper;

        public JcaPGPKeyPairGenerator(int version, Date creationTime, OperatorHelper helper, SecureRandom random)
        {
            super(version, creationTime, random, new JcaKeyFingerprintCalculator());
            this.helper = helper;
        }

        @Override
        public PGPKeyPair generateRsaKeyPair(BigInteger exponent, int bitStrength)
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("RSA");
                gen.initialize(new RSAKeyGenParameterSpec(bitStrength, exponent));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate RSA key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateEd25519KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("EDDSA");
                gen.initialize(new EdDSAParameterSpec("Ed25519"));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate Ed25519 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateEd448KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("EDDSA");
                gen.initialize(new EdDSAParameterSpec("Ed448"));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.Ed448, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate Ed448 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateX25519KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("XDH");
                gen.initialize(new XDHParameterSpec("X25519"));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.X25519, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate X25519 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateX448KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("XDH");
                gen.initialize(new XDHParameterSpec("X448"));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.X448, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate X448 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateMLDSA65Ed25519KeyPair()
            throws PGPException
        {
            return generateMLDSACompositeKeyPair(PublicKeyAlgorithmTags.MLDSA65_Ed25519, "Ed25519", MLDSAParameterSpec.ml_dsa_65);
        }

        @Override
        public PGPKeyPair generateMLDSA87Ed448KeyPair()
            throws PGPException
        {
            return generateMLDSACompositeKeyPair(PublicKeyAlgorithmTags.MLDSA87_Ed448, "Ed448", MLDSAParameterSpec.ml_dsa_87);
        }

        @Override
        public PGPKeyPair generateSLHDSAShake128sKeyPair()
            throws PGPException
        {
            return generateSLHDSAKeyPair(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s, SLHDSAParameterSpec.slh_dsa_shake_128s);
        }

        @Override
        public PGPKeyPair generateSLHDSAShake128fKeyPair()
            throws PGPException
        {
            return generateSLHDSAKeyPair(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, SLHDSAParameterSpec.slh_dsa_shake_128f);
        }

        @Override
        public PGPKeyPair generateSLHDSAShake256sKeyPair()
            throws PGPException
        {
            return generateSLHDSAKeyPair(PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s, SLHDSAParameterSpec.slh_dsa_shake_256s);
        }

        @Override
        public PGPKeyPair generateMLKEM768X25519KeyPair()
            throws PGPException
        {
            return generateMLKEMCompositeKeyPair(PublicKeyAlgorithmTags.MLKEM768_X25519, "X25519", MLKEMParameterSpec.ml_kem_768);
        }

        @Override
        public PGPKeyPair generateMLKEM1024X448KeyPair()
            throws PGPException
        {
            return generateMLKEMCompositeKeyPair(PublicKeyAlgorithmTags.MLKEM1024_X448, "X448", MLKEMParameterSpec.ml_kem_1024);
        }

        /**
         * RFC 9980 sec. 5.2.1: the ML-DSA and the EdDSA component keys are generated independently.
         */
        private PGPKeyPair generateMLDSACompositeKeyPair(int algorithm, String curveName, MLDSAParameterSpec mldsaSpec)
            throws PGPException
        {
            checkPQCKeyVersion(algorithm);
            try
            {
                KeyPairGenerator eddsaGen = helper.createKeyPairGenerator("EDDSA");
                eddsaGen.initialize(new EdDSAParameterSpec(curveName), random);
                KeyPair eddsaKp = eddsaGen.generateKeyPair();

                KeyPairGenerator mldsaGen = helper.createKeyPairGenerator("ML-DSA");
                mldsaGen.initialize(mldsaSpec, random);
                KeyPair mldsaKp = mldsaGen.generateKeyPair();

                return new JcaPGPKeyPair(version, algorithm, compose(eddsaKp, mldsaKp), creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate ML-DSA + " + curveName + " key pair", e);
            }
        }

        private PGPKeyPair generateSLHDSAKeyPair(int algorithm, SLHDSAParameterSpec spec)
            throws PGPException
        {
            checkPQCKeyVersion(algorithm);
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("SLH-DSA");
                gen.initialize(spec, random);
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, algorithm, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate " + spec.getName() + " key pair", e);
            }
        }

        /**
         * RFC 9980 sec. 4.2.2: the ML-KEM and the ECDH component keys are generated independently.
         */
        private PGPKeyPair generateMLKEMCompositeKeyPair(int algorithm, String curveName, MLKEMParameterSpec mlkemSpec)
            throws PGPException
        {
            checkPQCKeyVersion(algorithm);
            try
            {
                KeyPairGenerator xdhGen = helper.createKeyPairGenerator("XDH");
                xdhGen.initialize(new XDHParameterSpec(curveName), random);
                KeyPair xdhKp = xdhGen.generateKeyPair();

                KeyPairGenerator mlkemGen = helper.createKeyPairGenerator("ML-KEM");
                mlkemGen.initialize(mlkemSpec, random);
                KeyPair mlkemKp = mlkemGen.generateKeyPair();

                return new JcaPGPKeyPair(version, algorithm, compose(xdhKp, mlkemKp), creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate ML-KEM + " + curveName + " key pair", e);
            }
        }

        private static KeyPair compose(KeyPair traditional, KeyPair postQuantum)
        {
            return new KeyPair(
                new CompositePublicKey(new PublicKey[]{ traditional.getPublic(), postQuantum.getPublic() }),
                new CompositePrivateKey(new PrivateKey[]{ traditional.getPrivate(), postQuantum.getPrivate() }));
        }

        @Override
        public PGPKeyPair generateLegacyEd25519KeyPair()
            throws PGPException
        {
            if (version == PublicKeyPacket.VERSION_6)
            {
                throw new PGPException("An implementation MUST NOT generate a v6 LegacyEd25519 key pair.");
            }

            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("EDDSA");
                gen.initialize(new EdDSAParameterSpec("Ed25519"));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.EDDSA_LEGACY, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate LegacyEd25519 key pair.");
            }
        }

        @Override
        public PGPKeyPair generateLegacyX25519KeyPair()
            throws PGPException
        {
            if (version == PublicKeyPacket.VERSION_6)
            {
                throw new PGPException("An implementation MUST NOT generate a v6 LegacyX25519 key pair.");
            }

            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("XDH");
                gen.initialize(new XDHParameterSpec("X25519"));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.ECDH, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate LegacyX25519 key pair.", e);
            }
        }

        @Override
        public PGPKeyPair generateECDHKeyPair(ASN1ObjectIdentifier curveOID)
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("ECDH");
                String curveName = ECUtil.getCurveName(curveOID);
                gen.initialize(new ECNamedCurveGenParameterSpec(curveName));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.ECDH, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate ECDH key pair.", e);
            }
        }

        @Override
        public PGPKeyPair generateECDSAKeyPair(ASN1ObjectIdentifier curveOID)
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("ECDSA");
                String curveName = ECUtil.getCurveName(curveOID);
                gen.initialize(new ECNamedCurveGenParameterSpec(curveName));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.ECDSA, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate ECDSA key pair.", e);
            }
        }
    }
}
