package org.bouncycastle.crypto.hpke;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.agreement.BasicRawAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

class DHKEM
    extends KEM
{
    private AsymmetricCipherKeyPairGenerator kpGen;

    private RawAgreement rawAgreement;

    // kem ids
    private final short kemId;

    private HKDF hkdf;
    private byte bitmask;
    private int Nsk;
    private int Nsecret;
    private int Nenc;

    ECDomainParameters domainParams;

    protected DHKEM(short kemid)
    {
        this.kemId = kemid;

        switch (kemid)
        {
        case HPKE.kem_P256_SHA256:
            this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA256);
            domainParams = getDomainParameters("P-256");
            rawAgreement = new BasicRawAgreement(new ECDHCBasicAgreement());
            bitmask = (byte)0xff;
            Nsk = 32;
            Nsecret = 32;
            Nenc = 65;

            this.kpGen = new ECKeyPairGenerator();
            this.kpGen.init(new ECKeyGenerationParameters(domainParams, getSecureRandom()));

            break;
        case HPKE.kem_P384_SHA348:
            this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA384);
            domainParams = getDomainParameters("P-384");
            rawAgreement = new BasicRawAgreement(new ECDHCBasicAgreement());
            bitmask = (byte)0xff;
            Nsk = 48;
            Nsecret = 48;
            Nenc = 97;

            this.kpGen = new ECKeyPairGenerator();
            this.kpGen.init(new ECKeyGenerationParameters(domainParams, getSecureRandom()));

            break;
        case HPKE.kem_P521_SHA512:
            this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA512);
            domainParams = getDomainParameters("P-521");
            rawAgreement = new BasicRawAgreement(new ECDHCBasicAgreement());
            bitmask = 0x01;
            Nsk = 66;
            Nsecret = 64;
            Nenc = 133;

            this.kpGen = new ECKeyPairGenerator();
            this.kpGen.init(new ECKeyGenerationParameters(domainParams, getSecureRandom()));

            break;
        case HPKE.kem_X25519_SHA256:
            this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA256);
            rawAgreement = new X25519Agreement();
            Nsecret = 32;
            Nsk = 32;
            Nenc = 32;

            this.kpGen = new X25519KeyPairGenerator();
            this.kpGen.init(new X25519KeyGenerationParameters(getSecureRandom()));

            break;
        case HPKE.kem_X448_SHA512:
            this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA512);
            rawAgreement = new X448Agreement();
            Nsecret = 64;
            Nsk = 56;
            Nenc = 56;

            this.kpGen = new X448KeyPairGenerator();
            this.kpGen.init(new X448KeyGenerationParameters(getSecureRandom()));

            break;
        default:
            throw new IllegalArgumentException("invalid kem id");
        }
    }

    public byte[] SerializePublicKey(AsymmetricKeyParameter key)
    {
        switch (kemId)
        {
        case HPKE.kem_P256_SHA256:
        case HPKE.kem_P384_SHA348:
        case HPKE.kem_P521_SHA512:
            /*
             * RFC 9180 7.1.1. For P-256, P-384, and P-521, the SerializePublicKey() function of the KEM performs
             * the uncompressed Elliptic-Curve-Point-to-Octet-String conversion according to [SECG].
             */
            return ((ECPublicKeyParameters)key).getQ().getEncoded(false);
        case HPKE.kem_X448_SHA512:
            return ((X448PublicKeyParameters)key).getEncoded();
        case HPKE.kem_X25519_SHA256:
            return ((X25519PublicKeyParameters)key).getEncoded();
        default:
            throw new IllegalStateException("invalid kem id");
        }
    }

    public byte[] SerializePrivateKey(AsymmetricKeyParameter key)
    {
        switch (kemId)
        {
        case HPKE.kem_P256_SHA256:
        case HPKE.kem_P384_SHA348:
        case HPKE.kem_P521_SHA512:
        {
            /*
             * RFC 9180 7.1.2. For P-256, P-384, and P-521, the SerializePrivateKey() function of the KEM
             * performs the Field-Element-to-Octet-String conversion according to [SECG].
             */
            return BigIntegers.asUnsignedByteArray(Nsk, ((ECPrivateKeyParameters)key).getD());
        }
        case HPKE.kem_X448_SHA512:
        {
            /*
             * RFC 9180 7.1.2. For [..] X448 [..]. The SerializePrivateKey() function MUST clamp its output
             * [..].
             * 
             * NOTE: Our X448 implementation clamps generated keys, but de-serialized keys are preserved as is
             * (clamping applied only during usage).
             */
            byte[] encoded = ((X448PrivateKeyParameters)key).getEncoded();
            X448.clampPrivateKey(encoded);
            return encoded;
        }
        case HPKE.kem_X25519_SHA256:
        {
            /*
             * RFC 9180 7.1.2. For X25519 [..]. The SerializePrivateKey() function MUST clamp its output [..].
             * 
             * NOTE: Our X25519 implementation clamps generated keys, but de-serialized keys are preserved as
             * is (clamping applied only during usage).
             */
            byte[] encoded = ((X25519PrivateKeyParameters)key).getEncoded();
            X25519.clampPrivateKey(encoded);
            return encoded;
        }
        default:
            throw new IllegalStateException("invalid kem id");
        }
    }

    public AsymmetricKeyParameter DeserializePublicKey(byte[] pkEncoded)
    {
        if (pkEncoded == null)
        {
            throw new NullPointerException("'pkEncoded' cannot be null");
        }
        if (pkEncoded.length != Nenc)
        {
            throw new IllegalArgumentException("'pkEncoded' has invalid length");
        }

        switch (kemId)
        {
        case HPKE.kem_P256_SHA256:
        case HPKE.kem_P384_SHA348:
        case HPKE.kem_P521_SHA512:
            /*
             * RFC 9180 7.1.1. For P-256, P-384, and P-521 [..]. DeserializePublicKey() performs the
             * uncompressed Octet-String-to-Elliptic-Curve-Point conversion.
             */
            if (pkEncoded[0] != 0x04) // "0x04" is the marker for an uncompressed encoding
            {
                throw new IllegalArgumentException("'pkEncoded' has invalid format");
            }

            ECPoint G = domainParams.getCurve().decodePoint(pkEncoded);
            return new ECPublicKeyParameters(G, domainParams);
        case HPKE.kem_X448_SHA512:
            return new X448PublicKeyParameters(pkEncoded);
        case HPKE.kem_X25519_SHA256:
            return new X25519PublicKeyParameters(pkEncoded);
        default:
            throw new IllegalStateException("invalid kem id");
        }
    }

    public AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
    {
        if (skEncoded == null)
        {
            throw new NullPointerException("'skEncoded' cannot be null");
        }
        if (skEncoded.length != Nsk)
        {
            throw new IllegalArgumentException("'skEncoded' has invalid length");
        }

        AsymmetricKeyParameter pubParam = null;

        if (pkEncoded != null)
        {
            pubParam = DeserializePublicKey(pkEncoded);
        }

        switch (kemId)
        {
        case HPKE.kem_P256_SHA256:
        case HPKE.kem_P384_SHA348:
        case HPKE.kem_P521_SHA512:
            /*
             * RFC 9180 7.1.2. For P-256, P-384, and P-521 [..]. DeserializePrivateKey() performs the Octet-
             * String-to-Field-Element conversion according to [SECG].
             */
            BigInteger d = new BigInteger(1, skEncoded);
            ECPrivateKeyParameters ec = new ECPrivateKeyParameters(d, domainParams);

            if (pubParam == null)
            {
                ECPoint Q = new FixedPointCombMultiplier().multiply(domainParams.getG(), ((ECPrivateKeyParameters)ec).getD());
                pubParam = new ECPublicKeyParameters(Q, domainParams);
            }
            return new AsymmetricCipherKeyPair(pubParam, ec);
        case HPKE.kem_X448_SHA512:
            X448PrivateKeyParameters x448 = new X448PrivateKeyParameters(skEncoded);
            if (pubParam == null)
            {
                pubParam = x448.generatePublicKey();
            }
            return new AsymmetricCipherKeyPair(pubParam, x448);
        case HPKE.kem_X25519_SHA256:
            X25519PrivateKeyParameters x25519 = new X25519PrivateKeyParameters(skEncoded);
            if (pubParam == null)
            {
                pubParam = x25519.generatePublicKey();
            }
            return new AsymmetricCipherKeyPair(pubParam, x25519);
        default:
            throw new IllegalStateException("invalid kem id");
        }
    }

    int getEncryptionSize()
    {
        return Nenc;
    }

    private boolean validateSk(BigInteger d)
    {
        BigInteger n = domainParams.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        if (d.compareTo(BigInteger.valueOf(1)) < 0 || (d.compareTo(n) >= 0))
        {
            return false;
        }

        if (WNafUtil.getNafWeight(d) < minWeight)
        {
            return false;
        }

        return true;
    }

    public AsymmetricCipherKeyPair GeneratePrivateKey()
    {
        return kpGen.generateKeyPair(); // todo: can be replaced with deriveKeyPair(random)
    }

    public AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
    {
//        if (ikm.length < Nsk)
//        {
//            throw new IllegalArgumentException("input keying material should have length at least " + Nsk + " bytes");
//        }
        byte[] suiteID = Arrays.concatenate(Strings.toByteArray("KEM"), Pack.shortToBigEndian(kemId));
        switch (kemId)
        {
        case HPKE.kem_P256_SHA256:
        case HPKE.kem_P384_SHA348:
        case HPKE.kem_P521_SHA512:
        {
            byte[] dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
            byte[] counterArray = new byte[1];
            for (int counter = 0; counter < 256; ++counter)
            {
                counterArray[0] = (byte)counter;
                byte[] bytes = hkdf.LabeledExpand(dkp_prk, suiteID, "candidate", counterArray, Nsk);
                bytes[0] = (byte)(bytes[0] & bitmask);

                // generating keypair
                BigInteger d = new BigInteger(1, bytes);
                if (validateSk(d))
                {
                    ECPoint Q = new FixedPointCombMultiplier().multiply(domainParams.getG(), d);
                    ECPrivateKeyParameters sk = new ECPrivateKeyParameters(d, domainParams);
                    ECPublicKeyParameters pk = new ECPublicKeyParameters(Q, domainParams);
                    return new AsymmetricCipherKeyPair(pk, sk);
                }
            }
            throw new IllegalStateException("DeriveKeyPairError");
        }
        case HPKE.kem_X448_SHA512:
        {
            byte[] dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
            byte[] x448sk = hkdf.LabeledExpand(dkp_prk, suiteID, "sk", null, Nsk);
            X448PrivateKeyParameters x448params = new X448PrivateKeyParameters(x448sk);
            return new AsymmetricCipherKeyPair(x448params.generatePublicKey(), x448params);
        }
        case HPKE.kem_X25519_SHA256:
        {
            byte[] dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
            byte[] skBytes = hkdf.LabeledExpand(dkp_prk, suiteID, "sk", null, Nsk);
            X25519PrivateKeyParameters sk = new X25519PrivateKeyParameters(skBytes);
            return new AsymmetricCipherKeyPair(sk.generatePublicKey(), sk);
        }
        default:
            throw new IllegalStateException("invalid kem id");
        }
    }

    protected byte[][] Encap(AsymmetricKeyParameter pkR)
    {
        return Encap(pkR, kpGen.generateKeyPair());// todo: can be replaced with deriveKeyPair(random)
    }

    protected byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE)
    {
        byte[][] output = new byte[2][];

        // DH
        byte[] secret = calculateRawAgreement(rawAgreement, kpE.getPrivate(), pkR);

        byte[] enc = SerializePublicKey(kpE.getPublic());
        byte[] pkRm = SerializePublicKey(pkR);
        byte[] KEMContext = Arrays.concatenate(enc, pkRm);

        byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);

        output[0] = sharedSecret;
        output[1] = enc;
        return output;
    }

    protected byte[] Decap(byte[] enc, AsymmetricCipherKeyPair kpR)
    {
        AsymmetricKeyParameter pkE = DeserializePublicKey(enc);

        // DH
        byte[] secret = calculateRawAgreement(rawAgreement, kpR.getPrivate(), pkE);

        byte[] pkRm = SerializePublicKey(kpR.getPublic());
        byte[] KEMContext = Arrays.concatenate(enc, pkRm);

        return ExtractAndExpand(secret, KEMContext);
    }

    protected byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
    {
        byte[][] output = new byte[2][];

        AsymmetricCipherKeyPair kpE = kpGen.generateKeyPair(); // todo: can be replaced with deriveKeyPair(random)

        // DH(skE, pkR)
        rawAgreement.init(kpE.getPrivate());
        int agreementSize = rawAgreement.getAgreementSize();

        byte[] secret = new byte[agreementSize * 2];

        rawAgreement.calculateAgreement(pkR, secret, 0);

        // DH(skS, pkR)
        rawAgreement.init(kpS.getPrivate());
        if (agreementSize != rawAgreement.getAgreementSize())
        {
            throw new IllegalStateException();
        }

        rawAgreement.calculateAgreement(pkR, secret, agreementSize);

        byte[] enc = SerializePublicKey(kpE.getPublic());

        byte[] pkRm = SerializePublicKey(pkR);
        byte[] pkSm = SerializePublicKey(kpS.getPublic());
        byte[] KEMContext = Arrays.concatenate(enc, pkRm, pkSm);

        byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);

        output[0] = sharedSecret;
        output[1] = enc;
        return output;
    }

    protected byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS)
    {
        AsymmetricKeyParameter pkE = DeserializePublicKey(enc);

        rawAgreement.init(kpR.getPrivate());

        int agreementSize = rawAgreement.getAgreementSize();
        byte[] secret = new byte[agreementSize * 2];

        // DH(skR, pkE)
        rawAgreement.calculateAgreement(pkE, secret, 0);

        // DH(skR, pkS)
        rawAgreement.calculateAgreement(pkS, secret, agreementSize);

        byte[] pkRm = SerializePublicKey(kpR.getPublic());
        byte[] pkSm = SerializePublicKey(pkS);
        byte[] KEMContext = Arrays.concatenate(enc, pkRm, pkSm);

        return ExtractAndExpand(secret, KEMContext);
    }

    private byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
    {
        byte[] suiteID = Arrays.concatenate(Strings.toByteArray("KEM"), Pack.shortToBigEndian(kemId));

        byte[] eae_prk = hkdf.LabeledExtract(null, suiteID, "eae_prk", dh);

        return hkdf.LabeledExpand(eae_prk, suiteID, "shared_secret", kemContext, Nsecret);
    }

    private static byte[] calculateRawAgreement(RawAgreement rawAgreement, AsymmetricKeyParameter privateKey,
        AsymmetricKeyParameter publicKey)
    {
        rawAgreement.init(privateKey);
        byte[] z = new byte[rawAgreement.getAgreementSize()];
        rawAgreement.calculateAgreement(publicKey, z, 0);
        return z;
    }

    private static ECDomainParameters getDomainParameters(String curveName)
    {
        return new ECDomainParameters(CustomNamedCurves.getByName(curveName));
    }

    private static SecureRandom getSecureRandom()
    {
        return CryptoServicesRegistrar.getSecureRandom();
    }
}
