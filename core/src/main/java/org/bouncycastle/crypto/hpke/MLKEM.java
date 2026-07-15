package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

/**
 * ML-KEM as an HPKE KEM per draft-connolly-cfrg-hpke-mlkem.
 * <p>
 * The private key wire format is the 64-byte seed {@code (d, z)} of FIPS 203;
 * {@code DeriveKeyPair} requires an ikm of exactly 64 bytes, used directly as
 * that seed. ML-KEM is not an authenticated KEM, so the auth and auth_psk
 * modes are not supported.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-hpke-mlkem/">ML-KEM for HPKE</a>
 */
class MLKEM
    extends KEM
{
    private final MLKEMParameters parameters;
    private final int Nenc;
    private final int Npk;

    private static final int Nsk = 64;

    MLKEM(short kemid)
    {
        switch (kemid)
        {
        case HPKE.kem_ML_KEM_512:
            parameters = MLKEMParameters.ml_kem_512;
            Nenc = 768;
            Npk = 800;
            break;
        case HPKE.kem_ML_KEM_768:
            parameters = MLKEMParameters.ml_kem_768;
            Nenc = 1088;
            Npk = 1184;
            break;
        case HPKE.kem_ML_KEM_1024:
            parameters = MLKEMParameters.ml_kem_1024;
            Nenc = 1568;
            Npk = 1568;
            break;
        default:
            throw new IllegalArgumentException("invalid kem id");
        }
    }

    AsymmetricCipherKeyPair GeneratePrivateKey()
    {
        MLKEMKeyPairGenerator kpGen = new MLKEMKeyPairGenerator();
        kpGen.init(new MLKEMKeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), parameters));
        return kpGen.generateKeyPair();
    }

    AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
    {
        /*
         * draft-connolly-cfrg-hpke-mlkem: DeriveKeyPair(ikm) takes an ikm of exactly 64 bytes
         * and invokes ML-KEM.KeyGen_internal(ikm[0:32], ikm[32:64]).
         */
        if (ikm == null)
        {
            throw new NullPointerException("'ikm' cannot be null");
        }
        if (ikm.length != Nsk)
        {
            throw new IllegalArgumentException("'ikm' must be " + Nsk + " bytes");
        }

        MLKEMPrivateKeyParameters sk = new MLKEMPrivateKeyParameters(parameters, ikm);
        return new AsymmetricCipherKeyPair(sk.getPublicKeyParameters(), sk);
    }

    byte[][] Encap(AsymmetricKeyParameter recipientPublicKey)
    {
        MLKEMGenerator generator = new MLKEMGenerator(CryptoServicesRegistrar.getSecureRandom());
        SecretWithEncapsulation secEnc = generator.generateEncapsulated(checkPublicKey(recipientPublicKey));

        byte[][] output = new byte[2][];
        output[0] = secEnc.getSecret();
        output[1] = secEnc.getEncapsulation();
        return output;
    }

    byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE)
    {
        throw new UnsupportedOperationException(
            "ML-KEM encapsulation does not use an ephemeral key pair; use Encap(pkR, ier) for deterministic encapsulation");
    }

    byte[][] Encap(AsymmetricKeyParameter pkR, byte[] ier)
    {
        if (ier == null || ier.length != 32)
        {
            throw new IllegalArgumentException("'ier' must be 32 bytes");
        }

        SecretWithEncapsulation secEnc = MLKEMGenerator.internalGenerateEncapsulated(checkPublicKey(pkR), ier);

        byte[][] output = new byte[2][];
        output[0] = secEnc.getSecret();
        output[1] = secEnc.getEncapsulation();
        return output;
    }

    byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
    {
        throw new UnsupportedOperationException("ML-KEM is not an authenticated KEM");
    }

    byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair)
    {
        MLKEMExtractor extractor = new MLKEMExtractor((MLKEMPrivateKeyParameters)recipientKeyPair.getPrivate());
        return extractor.extractSecret(encapsulatedKey);
    }

    byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS)
    {
        throw new UnsupportedOperationException("ML-KEM is not an authenticated KEM");
    }

    byte[] SerializePublicKey(AsymmetricKeyParameter publicKey)
    {
        return checkPublicKey(publicKey).getEncoded();
    }

    byte[] SerializePrivateKey(AsymmetricKeyParameter key)
    {
        byte[] seed = ((MLKEMPrivateKeyParameters)key).getSeed();
        if (seed == null)
        {
            throw new IllegalArgumentException("private key does not carry the (d, z) seed");
        }
        return seed;
    }

    AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey)
    {
        if (encodedPublicKey == null)
        {
            throw new NullPointerException("'pkEncoded' cannot be null");
        }
        if (encodedPublicKey.length != Npk)
        {
            throw new IllegalArgumentException("'pkEncoded' has invalid length");
        }

        return new MLKEMPublicKeyParameters(parameters, encodedPublicKey);
    }

    AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
    {
        if (skEncoded == null)
        {
            throw new NullPointerException("'skEncoded' cannot be null");
        }
        if (skEncoded.length != Nsk)
        {
            throw new IllegalArgumentException("'skEncoded' has invalid length");
        }

        MLKEMPublicKeyParameters pubParam = null;
        if (pkEncoded != null)
        {
            pubParam = (MLKEMPublicKeyParameters)DeserializePublicKey(pkEncoded);
        }

        MLKEMPrivateKeyParameters sk = new MLKEMPrivateKeyParameters(parameters, skEncoded, pubParam);

        if (pubParam == null)
        {
            pubParam = sk.getPublicKeyParameters();
        }

        return new AsymmetricCipherKeyPair(pubParam, sk);
    }

    int getEncryptionSize()
    {
        return Nenc;
    }

    private MLKEMPublicKeyParameters checkPublicKey(AsymmetricKeyParameter publicKey)
    {
        MLKEMPublicKeyParameters pk = (MLKEMPublicKeyParameters)publicKey;
        if (pk.getParameters() != parameters)
        {
            throw new IllegalArgumentException("public key parameters do not match KEM");
        }
        return pk;
    }
}
