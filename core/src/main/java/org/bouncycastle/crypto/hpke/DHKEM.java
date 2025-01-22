package org.bouncycastle.crypto.hpke;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.XDHBasicAgreement;
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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

class DHKEM
    extends KEM
{
    private AsymmetricCipherKeyPairGenerator kpGen;

    private BasicAgreement agreement;

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
            this.agreement = new ECDHCBasicAgreement();
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
            this.agreement = new ECDHCBasicAgreement();
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
            this.agreement = new ECDHCBasicAgreement();
            bitmask = 0x01;
            Nsk = 66;
            Nsecret = 64;
            Nenc = 133;

            this.kpGen = new ECKeyPairGenerator();
            this.kpGen.init(new ECKeyGenerationParameters(domainParams, getSecureRandom()));

            break;
        case HPKE.kem_X25519_SHA256:
            this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA256);
            this.agreement = new XDHBasicAgreement();
            Nsecret = 32;
            Nsk = 32;
            Nenc = 32;

            this.kpGen = new X25519KeyPairGenerator();
            this.kpGen.init(new X25519KeyGenerationParameters(getSecureRandom()));

            break;
        case HPKE.kem_X448_SHA512:
            this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA512);
            this.agreement = new XDHBasicAgreement();
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
            return BigIntegers.asUnsignedByteArray(Nsk, ((ECPrivateKeyParameters)key).getD());
        case HPKE.kem_X448_SHA512:
            return ((X448PrivateKeyParameters)key).getEncoded();
        case HPKE.kem_X25519_SHA256:
            return ((X25519PrivateKeyParameters)key).getEncoded();
        default:
            throw new IllegalStateException("invalid kem id");
        }
    }

    public AsymmetricKeyParameter DeserializePublicKey(byte[] encoded)
    {
        switch (kemId)
        {
        case HPKE.kem_P256_SHA256:
        case HPKE.kem_P384_SHA348:
        case HPKE.kem_P521_SHA512:
            // TODO Does the encoding have to be uncompressed? (i.e. encoded.length MUST be Nenc?)
            ECPoint G = domainParams.getCurve().decodePoint(encoded);
            return new ECPublicKeyParameters(G, domainParams);
        case HPKE.kem_X448_SHA512:
            return new X448PublicKeyParameters(encoded);
        case HPKE.kem_X25519_SHA256:
            return new X25519PublicKeyParameters(encoded);
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
        byte[] secret = calculateAgreement(agreement, kpE.getPrivate(), pkR);

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
        byte[] secret = calculateAgreement(agreement, kpR.getPrivate(), pkE);

        byte[] pkRm = SerializePublicKey(kpR.getPublic());
        byte[] KEMContext = Arrays.concatenate(enc, pkRm);

        return ExtractAndExpand(secret, KEMContext);
    }

    protected byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
    {
        byte[][] output = new byte[2][];

        AsymmetricCipherKeyPair kpE = kpGen.generateKeyPair(); // todo: can be replaced with deriveKeyPair(random)

        // DH(skE, pkR)
        byte[] secret1 = calculateAgreement(agreement, kpE.getPrivate(), pkR);

        // DH(skS, pkR)
        byte[] secret2 = calculateAgreement(agreement, kpS.getPrivate(), pkR);

        byte[] secret = Arrays.concatenate(secret1, secret2);
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

        // DH(skR, pkE)
        byte[] secret1 = calculateAgreement(agreement, kpR.getPrivate(), pkE);

        // DH(skR, pkS)
        byte[] secret2 = calculateAgreement(agreement, kpR.getPrivate(), pkS);

        byte[] secret = Arrays.concatenate(secret1, secret2);

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

    private static byte[] calculateAgreement(BasicAgreement agreement, AsymmetricKeyParameter privateKey,
        AsymmetricKeyParameter publicKey)
    {
        agreement.init(privateKey);
        BigInteger z = agreement.calculateAgreement(publicKey);
        return BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), z);
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
