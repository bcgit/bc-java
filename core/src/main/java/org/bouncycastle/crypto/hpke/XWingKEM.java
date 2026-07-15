package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * X-Wing (X25519 / ML-KEM-768 hybrid) as an HPKE KEM per draft-connolly-cfrg-xwing-kem.
 * <p>
 * The private key wire format is the 32-byte X-Wing seed; {@code DeriveKeyPair}
 * derives that seed as SHAKE256(ikm, 32). X-Wing is not an authenticated KEM,
 * so the auth and auth_psk modes are not supported.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">X-Wing KEM</a>
 */
class XWingKEM
    extends KEM
{
    private static final int Nsk = 32;
    private static final int Npk = 1216;
    private static final int Nenc = 1120;

    // Encapsulation randomness: 32 bytes for ML-KEM-768, 32 bytes for the ephemeral X25519 key.
    private static final int Neseed = 64;

    XWingKEM()
    {
    }

    AsymmetricCipherKeyPair GeneratePrivateKey()
    {
        XWingKeyPairGenerator kpGen = new XWingKeyPairGenerator();
        kpGen.init(new XWingKeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom()));
        return kpGen.generateKeyPair();
    }

    AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
    {
        /*
         * draft-connolly-cfrg-xwing-kem: DeriveKeyPair(ikm) with ikm of at least 32 octets
         * generates the key pair from the seed SHAKE256(ikm, 32).
         */
        if (ikm == null)
        {
            throw new NullPointerException("'ikm' cannot be null");
        }
        if (ikm.length < Nsk)
        {
            throw new IllegalArgumentException("'ikm' must be at least " + Nsk + " bytes");
        }

        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(ikm, 0, ikm.length);
        byte[] seed = new byte[Nsk];
        shake.doFinal(seed, 0, seed.length);

        return keyPairFromSeed(seed);
    }

    byte[][] Encap(AsymmetricKeyParameter recipientPublicKey)
    {
        return encap(recipientPublicKey, new XWingKEMGenerator(CryptoServicesRegistrar.getSecureRandom()));
    }

    byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE)
    {
        throw new UnsupportedOperationException(
            "X-Wing encapsulation does not use an ephemeral key pair; use Encap(pkR, eseed) for deterministic encapsulation");
    }

    byte[][] Encap(AsymmetricKeyParameter pkR, byte[] ier)
    {
        if (ier == null || ier.length != Neseed)
        {
            throw new IllegalArgumentException("'ier' must be " + Neseed + " bytes");
        }

        return encap(pkR, new XWingKEMGenerator(new FixedSecureRandom(ier)));
    }

    private byte[][] encap(AsymmetricKeyParameter pkR, XWingKEMGenerator generator)
    {
        SecretWithEncapsulation secEnc = generator.generateEncapsulated((XWingPublicKeyParameters)pkR);

        byte[][] output = new byte[2][];
        output[0] = secEnc.getSecret();
        output[1] = secEnc.getEncapsulation();
        return output;
    }

    byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
    {
        throw new UnsupportedOperationException("X-Wing is not an authenticated KEM");
    }

    byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair)
    {
        if (encapsulatedKey == null)
        {
            throw new NullPointerException("'encapsulatedKey' cannot be null");
        }
        if (encapsulatedKey.length != Nenc)
        {
            throw new IllegalArgumentException("'encapsulatedKey' has invalid length");
        }

        XWingKEMExtractor extractor = new XWingKEMExtractor((XWingPrivateKeyParameters)recipientKeyPair.getPrivate());
        return extractor.extractSecret(encapsulatedKey);
    }

    byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS)
    {
        throw new UnsupportedOperationException("X-Wing is not an authenticated KEM");
    }

    byte[] SerializePublicKey(AsymmetricKeyParameter publicKey)
    {
        return ((XWingPublicKeyParameters)publicKey).getEncoded();
    }

    byte[] SerializePrivateKey(AsymmetricKeyParameter key)
    {
        return ((XWingPrivateKeyParameters)key).getSeed();
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

        return new XWingPublicKeyParameters(encodedPublicKey);
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

        AsymmetricCipherKeyPair kp = keyPairFromSeed(Arrays.clone(skEncoded));

        if (pkEncoded != null && !Arrays.areEqual(pkEncoded, SerializePublicKey(kp.getPublic())))
        {
            throw new IllegalArgumentException("'pkEncoded' does not match private key");
        }

        return kp;
    }

    int getEncryptionSize()
    {
        return Nenc;
    }

    private AsymmetricCipherKeyPair keyPairFromSeed(byte[] seed)
    {
        XWingKeyPairGenerator kpGen = new XWingKeyPairGenerator();
        kpGen.init(new XWingKeyGenerationParameters(new FixedSecureRandom(seed)));
        return kpGen.generateKeyPair();
    }
}
