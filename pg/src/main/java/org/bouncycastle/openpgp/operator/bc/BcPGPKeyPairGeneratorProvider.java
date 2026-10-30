package org.bouncycastle.openpgp.operator.bc;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;

public class BcPGPKeyPairGeneratorProvider
        extends PGPKeyPairGeneratorProvider
{
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    @Override
    public PGPKeyPairGenerator get(int version, Date creationTime)
    {
        return new BcPGPKeyPairGenerator(version, creationTime, random);
    }

    public BcPGPKeyPairGeneratorProvider setSecureRandom(SecureRandom random)
    {
        this.random = random;
        return this;
    }

    private static class BcPGPKeyPairGenerator
        extends PGPKeyPairGenerator
    {

        public BcPGPKeyPairGenerator(int version, Date creationTime, SecureRandom random)
        {
            super(version, creationTime, random, new BcKeyFingerprintCalculator());
        }

        @Override
        public PGPKeyPair generateRsaKeyPair(BigInteger exponent, int bitStrength)
            throws PGPException
        {
            RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
            gen.init(new RSAKeyGenerationParameters(exponent, random, bitStrength, 100));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateEd25519KeyPair()
            throws PGPException
        {
            Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
            gen.init(new Ed25519KeyGenerationParameters(random));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateEd448KeyPair()
            throws PGPException
        {
            Ed448KeyPairGenerator gen = new Ed448KeyPairGenerator();
            gen.init(new Ed448KeyGenerationParameters(random));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.Ed448, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateX25519KeyPair()
            throws PGPException
        {
            X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
            gen.init(new X25519KeyGenerationParameters(random));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.X25519, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateX448KeyPair()
            throws PGPException
        {
            X448KeyPairGenerator gen = new X448KeyPairGenerator();
            gen.init(new X448KeyGenerationParameters(random));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.X448, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateMLDSA65Ed25519KeyPair()
            throws PGPException
        {
            return generateMLDSACompositeKeyPair(PublicKeyAlgorithmTags.MLDSA65_Ed25519);
        }

        @Override
        public PGPKeyPair generateMLDSA87Ed448KeyPair()
            throws PGPException
        {
            return generateMLDSACompositeKeyPair(PublicKeyAlgorithmTags.MLDSA87_Ed448);
        }

        @Override
        public PGPKeyPair generateSLHDSAShake128sKeyPair()
            throws PGPException
        {
            return generateSLHDSAKeyPair(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s, SLHDSAParameters.shake_128s);
        }

        @Override
        public PGPKeyPair generateSLHDSAShake128fKeyPair()
            throws PGPException
        {
            return generateSLHDSAKeyPair(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, SLHDSAParameters.shake_128f);
        }

        @Override
        public PGPKeyPair generateSLHDSAShake256sKeyPair()
            throws PGPException
        {
            return generateSLHDSAKeyPair(PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s, SLHDSAParameters.shake_256s);
        }

        @Override
        public PGPKeyPair generateMLKEM768X25519KeyPair()
            throws PGPException
        {
            return generateMLKEMCompositeKeyPair(PublicKeyAlgorithmTags.MLKEM768_X25519);
        }

        @Override
        public PGPKeyPair generateMLKEM1024X448KeyPair()
            throws PGPException
        {
            return generateMLKEMCompositeKeyPair(PublicKeyAlgorithmTags.MLKEM1024_X448);
        }

        /**
         * RFC 9980 sec. 5.2.1: the ML-DSA and the EdDSA component keys are generated independently.
         */
        private PGPKeyPair generateMLDSACompositeKeyPair(int algorithm)
            throws PGPException
        {
            checkPQCKeyVersion(algorithm);

            AsymmetricCipherKeyPair eddsaKp;
            MLDSAParameters mldsaParams;
            if (algorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519)
            {
                Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
                gen.init(new Ed25519KeyGenerationParameters(random));
                eddsaKp = gen.generateKeyPair();
                mldsaParams = MLDSAParameters.ml_dsa_65;
            }
            else
            {
                Ed448KeyPairGenerator gen = new Ed448KeyPairGenerator();
                gen.init(new Ed448KeyGenerationParameters(random));
                eddsaKp = gen.generateKeyPair();
                mldsaParams = MLDSAParameters.ml_dsa_87;
            }

            MLDSAKeyPairGenerator mldsaGen = new MLDSAKeyPairGenerator();
            mldsaGen.init(new MLDSAKeyGenerationParameters(random, mldsaParams));
            AsymmetricCipherKeyPair mldsaKp = mldsaGen.generateKeyPair();

            return new BcPGPKeyPair(version, algorithm, compose(eddsaKp, mldsaKp), creationTime);
        }

        private PGPKeyPair generateSLHDSAKeyPair(int algorithm, SLHDSAParameters parameters)
            throws PGPException
        {
            checkPQCKeyVersion(algorithm);

            SLHDSAKeyPairGenerator gen = new SLHDSAKeyPairGenerator();
            gen.init(new SLHDSAKeyGenerationParameters(random, parameters));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, algorithm, keyPair, creationTime);
        }

        /**
         * RFC 9980 sec. 4.2.2: the ML-KEM and the ECDH component keys are generated independently.
         */
        private PGPKeyPair generateMLKEMCompositeKeyPair(int algorithm)
            throws PGPException
        {
            checkPQCKeyVersion(algorithm);

            AsymmetricCipherKeyPair ecdhKp;
            MLKEMParameters mlkemParams;
            if (algorithm == PublicKeyAlgorithmTags.MLKEM768_X25519)
            {
                X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                gen.init(new X25519KeyGenerationParameters(random));
                ecdhKp = gen.generateKeyPair();
                mlkemParams = MLKEMParameters.ml_kem_768;
            }
            else
            {
                X448KeyPairGenerator gen = new X448KeyPairGenerator();
                gen.init(new X448KeyGenerationParameters(random));
                ecdhKp = gen.generateKeyPair();
                mlkemParams = MLKEMParameters.ml_kem_1024;
            }

            MLKEMKeyPairGenerator mlkemGen = new MLKEMKeyPairGenerator();
            mlkemGen.init(new MLKEMKeyGenerationParameters(random, mlkemParams));
            AsymmetricCipherKeyPair mlkemKp = mlkemGen.generateKeyPair();

            return new BcPGPKeyPair(version, algorithm, compose(ecdhKp, mlkemKp), creationTime);
        }

        private static AsymmetricCipherKeyPair compose(AsymmetricCipherKeyPair traditional, AsymmetricCipherKeyPair postQuantum)
        {
            return new AsymmetricCipherKeyPair(
                new BcPGPCompositeKeyParameters(false, traditional.getPublic(), postQuantum.getPublic()),
                new BcPGPCompositeKeyParameters(true, traditional.getPrivate(), postQuantum.getPrivate()));
        }

        @Override
        public PGPKeyPair generateLegacyEd25519KeyPair()
            throws PGPException
        {
            if (version == PublicKeyPacket.VERSION_6)
            {
                throw new PGPException("An implementation MUST NOT generate a v6 LegacyEd25519 key pair.");
            }

            Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
            gen.init(new Ed25519KeyGenerationParameters(random));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.EDDSA_LEGACY, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateLegacyX25519KeyPair()
            throws PGPException
        {
            if (version == PublicKeyPacket.VERSION_6)
            {
                throw new PGPException("An implementation MUST NOT generate a v6 LegacyX25519 key pair.");
            }

            X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
            gen.init(new X25519KeyGenerationParameters(random));
            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.ECDH, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateECDHKeyPair(ASN1ObjectIdentifier curveOID)
            throws PGPException
        {
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            gen.init(new ECKeyGenerationParameters(
                new ECNamedDomainParameters(curveOID, getNamedCurveByOid(curveOID)),
                CryptoServicesRegistrar.getSecureRandom()));

            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.ECDH, keyPair, creationTime);
        }

        @Override
        public PGPKeyPair generateECDSAKeyPair(ASN1ObjectIdentifier curveOID)
            throws PGPException
        {
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            gen.init(new ECKeyGenerationParameters(
                new ECNamedDomainParameters(curveOID, getNamedCurveByOid(curveOID)),
                CryptoServicesRegistrar.getSecureRandom()));

            AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
            return new BcPGPKeyPair(version, PublicKeyAlgorithmTags.ECDSA, keyPair, creationTime);
        }
    }

    private static X9ECParameters getNamedCurveByOid(
        ASN1ObjectIdentifier oid)
    {
        X9ECParameters params = CustomNamedCurves.getByOID(oid);

        if (params == null)
        {
            params = ECNamedCurveTable.getByOID(oid);
        }

        return params;
    }
}
