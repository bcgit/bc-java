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
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
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
