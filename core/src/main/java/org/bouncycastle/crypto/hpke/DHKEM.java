package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.XDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;


public class DHKEM
{

    private AsymmetricCipherKeyPairGenerator kpGen;

    private BasicAgreement agreement;

    // kem ids
    private final short kemId;
    private static final short P256_SHA256 = 16;
    private static final short P384_SHA348 = 17;
    private static final short P521_SHA512 = 18;
    private static final short X25519_SHA256 = 32;
    private static final short X448_SHA512 = 33;

    private HKDF hkdf;
    private byte bitmask;
    private int Nsk;
    private int Nsecret;

    ECDomainParameters domainParams;


    protected DHKEM(short kemid)
            throws Exception
    {
        this.kemId = kemid;
        ECCurve curve;
        switch (kemid)
        {
            case P256_SHA256:
                this.hkdf = new HKDF((short) 1);
                curve = new SecP256R1Curve();
                domainParams = new ECDomainParameters(
                        curve,
                        curve.createPoint(
                                new BigInteger(1, Hex.decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")),
                                new BigInteger(1, Hex.decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
                        ),
                        curve.getOrder(),
                        curve.getCofactor(),
                        Hex.decode("c49d360886e704936a6678e1139d26b7819f7e90")
                );
                this.agreement = new ECDHCBasicAgreement();
                bitmask = (byte) 0xff;
                Nsk = 32;
                Nsecret = 32;

                this.kpGen = new ECKeyPairGenerator();
                this.kpGen.init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

                break;
            case P384_SHA348:
                this.hkdf = new HKDF((short) 2);
                curve = new SecP384R1Curve();
                domainParams = new ECDomainParameters(
                        curve,
                        curve.createPoint(
                                new BigInteger(1, Hex.decode("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")),
                                new BigInteger(1, Hex.decode("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"))
                        ),
                        curve.getOrder(),
                        curve.getCofactor(),
                        Hex.decode("a335926aa319a27a1d00896a6773a4827acdac73")
                );
                this.agreement = new ECDHCBasicAgreement();
                bitmask = (byte) 0xff;
                Nsk = 48;
                Nsecret = 48;

                this.kpGen = new ECKeyPairGenerator();
                this.kpGen.init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

                break;
            case P521_SHA512:
                this.hkdf = new HKDF((short) 3);

                curve = new SecP521R1Curve();
                domainParams = new ECDomainParameters(
                        curve,
                        curve.createPoint(
                                new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
                                new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)
                        ),
                        curve.getOrder(),
                        curve.getCofactor(),
                        Hex.decode("d09e8800291cb85396cc6717393284aaa0da64ba")
                );
                this.agreement = new ECDHCBasicAgreement();
                bitmask = 0x01;
                Nsk = 66;
                Nsecret = 64;

                this.kpGen = new ECKeyPairGenerator();
                this.kpGen.init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

                break;
            case X25519_SHA256:
                this.hkdf = new HKDF((short) 1);
                this.agreement = new XDHBasicAgreement();
                Nsecret = 32;

                this.kpGen = new X25519KeyPairGenerator();
                this.kpGen.init(new X25519KeyGenerationParameters(new SecureRandom()));

                break;
            case X448_SHA512:
                this.hkdf = new HKDF((short) 3);
                this.agreement = new XDHBasicAgreement();
                Nsecret = 64;

                this.kpGen = new X448KeyPairGenerator();
                this.kpGen.init(new X448KeyGenerationParameters(new SecureRandom()));

                break;
        }
    }

    private byte[] SerializePublicKey(AsymmetricKeyParameter key) throws Exception
    {

        switch (kemId)
        {
            case P256_SHA256:
            case P384_SHA348:
            case P521_SHA512:
                return ((ECPublicKeyParameters) key).getQ().getEncoded(false);
            case X448_SHA512:
                return ((X448PublicKeyParameters) key).getEncoded();
            case X25519_SHA256:
                return ((X25519PublicKeyParameters) key).getEncoded();
            default:
                throw new Exception("Invalid kem id");
        }
    }

    public AsymmetricKeyParameter DeserializePublicKey(byte[] encoded)
            throws Exception
    {
        switch (kemId)
        {
            case P256_SHA256:
            case P384_SHA348:
            case P521_SHA512:
                ECPoint G = domainParams.getCurve().decodePoint(encoded);
                return new ECPublicKeyParameters(G, domainParams);
            case X448_SHA512:
                return new X448PublicKeyParameters(encoded);
            case X25519_SHA256:
                return new X25519PublicKeyParameters(encoded);
            default:
                throw new Exception("Invalid kem id");
        }
    }

    public AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
            throws Exception
    {
        AsymmetricKeyParameter pubParam = DeserializePublicKey(pkEncoded);
        switch (kemId)
        {
            case P256_SHA256:
            case P384_SHA348:
            case P521_SHA512:
                BigInteger d = new BigInteger(1, skEncoded);
                return new AsymmetricCipherKeyPair(pubParam, new ECPrivateKeyParameters(d, ((ECPublicKeyParameters) pubParam).getParameters()));
            case X448_SHA512:
                return new AsymmetricCipherKeyPair(pubParam, new X448PrivateKeyParameters(skEncoded));
            case X25519_SHA256:
                return new AsymmetricCipherKeyPair(pubParam, new X25519PrivateKeyParameters(skEncoded));
            default:
                throw new Exception("Invalid kem id");
        }
    }

    private boolean ValidateSk(BigInteger d)
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
        return kpGen.generateKeyPair();
    }

    public AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
        throws Exception
    {
        byte[] suiteID = Arrays.concatenate(Hex.decode("KEM"), Pack.shortToBigEndian(kemId));
        switch(kemId)
        {
            case P256_SHA256:
            case P384_SHA348:
            case P521_SHA512:
                byte[] dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                int counter = 0;
                byte[] counterArray = new byte[1];
                while (true)
                {
                    if (counter > 255)
                    {
                        throw new Exception("DeriveKeyPairError");
                    }
                    counterArray[0] = (byte) counter; // todo check if this is the correct endian
                    byte[] bytes = hkdf.LabeledExpand(dkp_prk, suiteID,"candidate", counterArray, Nsk);
                    bytes[0] = (byte) (bytes[0] & bitmask);


                    // generating keypair
                    BigInteger d = new BigInteger(bytes);
                    if (ValidateSk(d))
                    {
                        ECPoint Q = new FixedPointCombMultiplier().multiply(domainParams.getG(), d);
                        ECPrivateKeyParameters sk = new ECPrivateKeyParameters(d, domainParams);
                        ECPublicKeyParameters pk = new ECPublicKeyParameters(Q, domainParams);
                        return new AsymmetricCipherKeyPair(pk, sk);
                    }

                    counter++;
                }
            case X448_SHA512:
                dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                byte[] x448sk = hkdf.LabeledExpand(dkp_prk, suiteID, "sk", null, Nsk);
                X448PrivateKeyParameters x448params = new X448PrivateKeyParameters(x448sk);
                return new AsymmetricCipherKeyPair(x448params.generatePublicKey(), x448params);

            case X25519_SHA256:
                dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                byte[] skBytes = hkdf.LabeledExpand(dkp_prk, suiteID, "sk", null, Nsk);
                X25519PrivateKeyParameters sk = new X25519PrivateKeyParameters(skBytes);

                return new AsymmetricCipherKeyPair(sk.generatePublicKey(), sk);
            default:
                throw new Exception("Invalid kem id");
        }
    }



    protected byte[][] Encap(AsymmetricKeyParameter pkR)
        throws Exception
    {
        byte[][] output = new byte[2][];
        //init here or in constructor
        AsymmetricCipherKeyPair kpE = kpGen.generateKeyPair();

        //DH
        agreement.init(kpE.getPrivate());

        byte[] secret = new byte[agreement.getFieldSize()];
        byte[] temp = agreement.calculateAgreement(pkR).toByteArray();; // add leading zeros
//        System.out.println("temp: " + Hex.toHexString(temp));
        if (temp.length <= secret.length)
        {
            System.arraycopy(temp, 0, secret, secret.length - temp.length, temp.length);
        }
        else
        {
            System.arraycopy(temp, temp.length - secret.length, secret, 0, secret.length);
        }

        byte[] enc = SerializePublicKey(kpE.getPublic());
        byte[] pkRm = SerializePublicKey(pkR);
        byte[] KEMContext = Arrays.concatenate(enc, pkRm);

        byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);

        output[0] = sharedSecret;
        output[1] = enc;
        return output;
    }

    protected byte[] Decap(byte[] enc, AsymmetricCipherKeyPair kpR)
        throws Exception
    {
        ////System.out.println("\nDecap");
        ////System.out.println("enc: " + Hex.toHexString(enc));

        AsymmetricKeyParameter pkE = DeserializePublicKey(enc);

        //DH
        agreement.init(kpR.getPrivate());

        ////System.out.println("size: " + agreement.getFieldSize());


        byte[] secret = new byte[agreement.getFieldSize()];
        byte[] temp = agreement.calculateAgreement(pkE).toByteArray(); // add leading zeros
//        System.out.println("temp: " + Hex.toHexString(temp));
        if (temp.length <= secret.length)
        {
            System.arraycopy(temp, 0, secret, secret.length - temp.length, temp.length);
        }
        else
        {
            System.arraycopy(temp, temp.length - secret.length, secret, 0, secret.length);
        }

        ////System.out.println("size: " + secret.length);
//        System.out.println("dh: " + Hex.toHexString(secret));

        byte[] pkRm = SerializePublicKey(kpR.getPublic());
        byte[] KEMContext = Arrays.concatenate(enc, pkRm);
//        System.out.println("pkRm: " + Hex.toHexString(pkRm));
//        System.out.println("KEMContext: " + Hex.toHexString(KEMContext));


        byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);
        return sharedSecret;
    }

    protected byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
        throws Exception
    {
        byte[][] output = new byte[2][];

        AsymmetricCipherKeyPair kpE = kpGen.generateKeyPair();


        // DH(skE, pkR)
        agreement.init(kpE.getPrivate());
        byte[] secret1 = new byte[agreement.getFieldSize()];
        byte[] temp = agreement.calculateAgreement(pkR).toByteArray();
        if (temp.length <= secret1.length)
        {
            System.arraycopy(temp, 0, secret1, secret1.length - temp.length, temp.length);
        }
        else
        {
            System.arraycopy(temp, temp.length - secret1.length, secret1, 0, secret1.length);
        }

        // DH(skS, pkR)
        agreement.init(kpS.getPrivate());
        byte[] secret2 = new byte[agreement.getFieldSize()];
        temp = agreement.calculateAgreement(pkR).toByteArray();
        if (temp.length <= secret2.length)
        {
            System.arraycopy(temp, 0, secret2, secret2.length - temp.length, temp.length);
        }
        else
        {
            System.arraycopy(temp, temp.length - secret2.length, secret2, 0, secret2.length);
        }

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

    protected byte[] AuthDecap(byte [] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS)
            throws Exception
    {
        AsymmetricKeyParameter pkE = DeserializePublicKey(enc);

        // DH(skR, pkE)
        agreement.init(kpR.getPrivate());

        byte[] secret1 = new byte[agreement.getFieldSize()];
        byte[] temp = agreement.calculateAgreement(pkE).toByteArray(); // add leading zeros
        if (temp.length <= secret1.length)
        {
            System.arraycopy(temp, 0, secret1, secret1.length - temp.length, temp.length);
        }
        else
        {
            System.arraycopy(temp, temp.length - secret1.length, secret1, 0, secret1.length);
        }

        // DH(skR, pkS)
        agreement.init(kpR.getPrivate());
        byte[] secret2 = new byte[agreement.getFieldSize()];
        temp = agreement.calculateAgreement(pkS).toByteArray();
        if (temp.length <= secret2.length)
        {
            System.arraycopy(temp, 0, secret2, secret2.length - temp.length, temp.length);
        }
        else
        {
            System.arraycopy(temp, temp.length - secret2.length, secret2, 0, secret2.length);
        }
        byte[] secret = Arrays.concatenate(secret1, secret2);

        byte[] pkRm = SerializePublicKey(kpR.getPublic());
        byte[] pkSm = SerializePublicKey(pkS);
        byte[] KEMContext = Arrays.concatenate(enc, pkRm, pkSm);

        byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);
        return sharedSecret;
    }

    private byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
            throws Exception
    {
//        System.out.println("\nExtract and Expand");
//        System.out.println("dh: " + Hex.toHexString(dh));
//        System.out.println("kemContext: " + Hex.toHexString(kemContext));

        byte[] suiteID = Arrays.concatenate("KEM".getBytes(), Pack.shortToBigEndian(kemId));
//        System.out.println("suiteID: " + Hex.toHexString(suiteID));

        byte[] eae_prk = hkdf.LabeledExtract(null, suiteID, "eae_prk", dh);
//        System.out.println("eae_prk: " + Hex.toHexString(eae_prk));

        byte[] sharedSecret = hkdf.LabeledExpand(eae_prk, suiteID, "shared_secret", kemContext, Nsecret);
//        System.out.println("dhLen: " + dh.length);
//        System.out.println();

        return sharedSecret;
    }
}
