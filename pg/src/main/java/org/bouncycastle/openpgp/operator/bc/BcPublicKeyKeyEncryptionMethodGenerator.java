package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.Ed25519PublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.BigIntegers;

/**
 * A method generator for supporting public key based encryption operations.
 */
public class BcPublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private static final byte X_HDR = 0x40;

    private SecureRandom random;
    private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

    /**
     * Create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key the public key to use for encryption.
     */
    public BcPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key)
    {
        super(key);
    }

    /**
     * Provide a user defined source of randomness.
     *
     * @param random the secure random to be used.
     * @return the current generator.
     */
    public BcPublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter cryptoPublicKey = keyConverter.getPublicKey(pubKey);
            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
            {
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();
                ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pubKeyPacket.getKey();

                byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyPacket,
                    new BcKeyFingerprintCalculator());

                if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                    gen.init(new X25519KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.init(ephKp.getPrivate());

                    byte[] secret = new byte[agreement.getAgreementSize()];
                    agreement.calculateAgreement(cryptoPublicKey, secret, 0);

                    byte[] ephPubEncoding = new byte[1 + X25519PublicKeyParameters.KEY_SIZE];
                    ephPubEncoding[0] = X_HDR;
                    ((X25519PublicKeyParameters)ephKp.getPublic()).encode(ephPubEncoding, 1);

                    return encryptSessionInfo(sessionInfo, secret, userKeyingMaterial, ephPubEncoding, ecPubKey.getHashAlgorithm(), ecPubKey.getSymmetricKeyAlgorithm());
                }
                else
                {
                    ECDomainParameters ecParams = ((ECPublicKeyParameters)cryptoPublicKey).getParameters();

                    ECKeyPairGenerator gen = new ECKeyPairGenerator();
                    gen.init(new ECKeyGenerationParameters(ecParams, random));

                    AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.init(ephKp.getPrivate());
                    BigInteger S = agreement.calculateAgreement(cryptoPublicKey);
                    byte[] secret = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), S);

                    byte[] ephPubEncoding = ((ECPublicKeyParameters)ephKp.getPublic()).getQ().getEncoded(false);

                    return encryptSessionInfo(sessionInfo, secret, userKeyingMaterial, ephPubEncoding, ecPubKey.getHashAlgorithm(), ecPubKey.getSymmetricKeyAlgorithm());
                }
            }
            else if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.X25519)
            {
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();

                byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyPacket, new BcKeyFingerprintCalculator(),
                    CryptlibObjectIdentifiers.curvey25519, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);

                X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                gen.init(new X25519KeyGenerationParameters(random));

                AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                X25519Agreement agreement = new X25519Agreement();
                agreement.init(ephKp.getPrivate());

                byte[] secret = new byte[agreement.getAgreementSize()];
                agreement.calculateAgreement(cryptoPublicKey, secret, 0);

                byte[] ephPubEncoding = new byte[ X25519PublicKeyParameters.KEY_SIZE];
                ((X25519PublicKeyParameters)ephKp.getPublic()).encode(ephPubEncoding, 0);

                return encryptSessionInfo(sessionInfo, secret, userKeyingMaterial, ephPubEncoding, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
            }
            else if ( pubKey.getAlgorithm() == PublicKeyAlgorithmTags.X448)
            {
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();
                byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyPacket, new BcKeyFingerprintCalculator(),
                    EdECObjectIdentifiers.id_X448, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256);
                X448KeyPairGenerator gen = new X448KeyPairGenerator();
                gen.init(new X448KeyGenerationParameters(random));

                AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                X448Agreement agreement = new X448Agreement();
                agreement.init(ephKp.getPrivate());

                byte[] secret = new byte[agreement.getAgreementSize()];
                agreement.calculateAgreement(cryptoPublicKey, secret, 0);

                byte[] ephPubEncoding = new byte[X448PublicKeyParameters.KEY_SIZE];

                ((X448PublicKeyParameters)ephKp.getPublic()).encode(ephPubEncoding, 0);

                return encryptSessionInfo(sessionInfo, secret, userKeyingMaterial, ephPubEncoding, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256);
            }
            else
            {
                AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(pubKey.getAlgorithm());

                c.init(true, new ParametersWithRandom(cryptoPublicKey, random));

                return c.processBlock(sessionInfo, 0, sessionInfo.length);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }
    }

    private byte[] encryptSessionInfo(byte[] sessionInfo, byte[] secret,
                                      byte[] userKeyingMaterial, byte[] ephPubEncoding, int hashAlgorithm, int symmetricKeyAlgorithm)
        throws IOException, PGPException
    {
        RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(
            new BcPGPDigestCalculatorProvider().get(hashAlgorithm), symmetricKeyAlgorithm);
        KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

        byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo, sessionKeyObfuscation);

        Wrapper c = BcImplProvider.createWrapper(symmetricKeyAlgorithm);
        c.init(true, new ParametersWithRandom(key, random));
        byte[] C = c.wrap(paddedSessionData, 0, paddedSessionData.length);

        return getSessionInfo(ephPubEncoding, C);
    }
}
