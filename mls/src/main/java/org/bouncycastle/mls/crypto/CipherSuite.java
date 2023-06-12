package org.bouncycastle.mls.crypto;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.hpke.AEAD;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CipherSuite {
    public static final short MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519  = 0x0001 ;
    public static final short MLS_128_DHKEMP256_AES128GCM_SHA256_P256  = 0x0002 ;
    public static final short MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519  = 0x0003 ;
    public static final short MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448  = 0x0004 ;
    public static final short MLS_256_DHKEMP521_AES256GCM_SHA512_P521  = 0x0005 ;
    public static final short MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448  = 0x0006 ;
    public static final short MLS_256_DHKEMP384_AES256GCM_SHA384_P384  = 0x0007 ;

    public interface KDF {
        int getHashLength();
        byte[] extract(byte[] salt, byte[] ikm);
        byte[] expand(byte [] prk, byte[] info, int length);
        byte[] expand(byte [] prk, int length);

        default byte[] expandWithLabel(byte[] secret, String label, byte[] context, int length) throws IOException
        {
            Secret.KDFLabel kdfLabelStr = new Secret.KDFLabel((short) length, label, context);
            byte[] kdfLabel = MLSOutputStream.encode(kdfLabelStr);
            return expand(secret, kdfLabel, length);
        }

    }
    public static class RefHash implements MLSOutputStream.Writable {
        public byte[] label;
        public byte[] value;

        public RefHash(byte[] label, byte[] value)
        {
            this.label = label;
            this.value = value;
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.writeOpaque(label);
            stream.writeOpaque(value);
        }
    }

    //SignContent
    //EncryptContent
    public static class GenericContent implements MLSOutputStream.Writable {

        private byte[] label;
        private byte[] content;

        public GenericContent(String label, byte[] content)
        {
            this.label = ("MLS 1.0 " + label).getBytes(StandardCharsets.UTF_8);
            this.content = content;
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException
        {
            stream.writeOpaque(label);
            stream.writeOpaque(content);
        }
    }


    public short getSuiteId()
    {
        return suiteId;
    }

    //TODO get from HKDF instead of defining it here.
    // might need to change the KDF functionalities
    static class HKDF implements KDF {
        private final HKDFBytesGenerator kdf;

        HKDF(Digest digest) {
            kdf = new HKDFBytesGenerator(digest);
        }

        @Override
        public int getHashLength() {
            return kdf.getDigest().getDigestSize();
        }

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) {
            return kdf.extractPRK(salt, ikm);
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) {
            byte[] okm = new byte[length];
            kdf.init(HKDFParameters.skipExtractParameters(prk, info));
            kdf.generateBytes(okm, 0, okm.length);
            return okm;
        }
        @Override
        public byte[] expand(byte[] prk, int length) {
            byte[] okm = new byte[length];
            kdf.init(HKDFParameters.defaultParameters(prk));
            kdf.generateBytes(okm, 0, okm.length);
            return okm;
        }


    }

    public static class AEAD
    {
        AEADCipher cipher;
        private final short aeadId;

        public AEAD(short aeadId)
        {
            this.aeadId = aeadId;

            switch (aeadId)
            {
                case HPKE.aead_AES_GCM128:
                case HPKE.aead_AES_GCM256:
                    cipher = new GCMBlockCipher(new AESEngine());
                    break;
                case HPKE.aead_CHACHA20_POLY1305:
                    cipher = new ChaCha20Poly1305();
                    break;
                case HPKE.aead_EXPORT_ONLY:
                    break;
            }
        }

        public int getKeySize()
        {
            switch (aeadId)
            {
                case HPKE.aead_AES_GCM128:
                    return 16;
                case HPKE.aead_AES_GCM256:
                case HPKE.aead_CHACHA20_POLY1305:
                    return 32;
            }
            return -1;
        }
        private int getTagSize()
        {
            switch (aeadId)
            {
                case HPKE.aead_AES_GCM128:
                case HPKE.aead_AES_GCM256:
                case HPKE.aead_CHACHA20_POLY1305:
                    return 16;
            }
            return -1;
        }

        public int getNonceSize()
        {
            switch (aeadId)
            {
                case HPKE.aead_AES_GCM128:
                case HPKE.aead_AES_GCM256:
                case HPKE.aead_CHACHA20_POLY1305:
                    return 12;
            }
            return -1;
        }
        public byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ct) throws InvalidCipherTextException
        {
            System.out.println("key: " + Hex.toHexString(key));
            System.out.println("nonce: " + Hex.toHexString(nonce));
            System.out.println("aad: " + Hex.toHexString(aad));
            System.out.println("ct: " + Hex.toHexString(ct));
            System.out.println(cipher.getOutputSize(ct.length));
//            org.bouncycastle.crypto.hpke.AEAD aead = new org.bouncycastle.crypto.hpke.AEAD(aeadId, key, nonce);
//            return aead.open(aad, ct);
//            int tagSize = getTagSize();
//            byte[] tag = Arrays.copyOfRange(ct, ct.length - tagSize, ct.length);
//            System.out.println(tag.length);
            CipherParameters params = new ParametersWithIV(new KeyParameter(key), nonce);
            cipher.init(false, params);
            cipher.processAADBytes(aad, 0, aad.length);

            byte[] pt = new byte[cipher.getOutputSize(ct.length)];
//            byte[] pt = new byte[cipher.getOutputSize(tag.length)];
//            byte[] pt = new byte[tagSize];
//            System.arraycopy(tag, 0, pt, 0, tagSize);

            int len = cipher.processBytes(ct, 0, ct.length, pt, 0);
            len += cipher.doFinal(pt, len);
            return pt;
        }
        public byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] pt) throws InvalidCipherTextException
        {
            CipherParameters params = new ParametersWithIV(new KeyParameter(key), nonce);
            cipher.init(true, params);
            cipher.processAADBytes(aad, 0, aad.length);

            byte[] ct = new byte[cipher.getOutputSize(pt.length)];
            int len = cipher.processBytes(pt, 0, pt.length, ct, 0);
            cipher.doFinal(ct, len);
            return ct;
        }
    }


    final KDF kdf;
    final AEAD aead;
    final HPKE hpke;

    final Signer signer;

    final Digest digest;

    final int sigAlgo;
    final short suiteId;
    ECDomainParameters domainParams;

    public static final int ecdsa = 3;
    public static final int ed25519 = 7;
    public static final int ed448 = 8;
    public CipherSuite(short suite) {
        // TODO Configure digest
        // TODO Configure KEM
        // TODO Configure Signature
//        new DSAPublicKeyParameters(y, dsaParams),
//                new DSAPrivateKeyParameters(x, dsaParams));
        ECCurve curve;

        suiteId = suite;

        switch (suite) {
            case MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
                kdf = new HKDF(new SHA256Digest());
                digest = new SHA256Digest();
                signer = new Ed25519Signer();
                sigAlgo = ed25519;

                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
                break;

            case MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
                kdf = new HKDF(new SHA256Digest());
                digest = new SHA256Digest();
                signer = new DSADigestSigner(new ECDSASigner(), digest);
                sigAlgo = ecdsa;

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

                hpke = new HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
                break;

            case MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
                kdf = new HKDF(new SHA256Digest());
                digest = new SHA256Digest();
                signer = new Ed25519Signer();
                sigAlgo = ed25519;

                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305);
                break;

            case MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
                kdf = new HKDF(new SHA384Digest());
                digest = new SHA384Digest();
                signer = new DSADigestSigner(new ECDSASigner(), digest);
                sigAlgo = ecdsa;

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

                hpke = new HPKE(HPKE.mode_base, HPKE.kem_P384_SHA348, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256);
                break;

            case MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
                kdf = new HKDF(new SHA512Digest());
                digest = new SHA512Digest();
                signer = new Ed448Signer(new byte[0]);
                sigAlgo = ed448;

                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256);
                break;

            case MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
                kdf = new HKDF(new SHA512Digest());
                digest = new SHA512Digest();
                signer = new DSADigestSigner(new ECDSASigner(), digest);
                sigAlgo = ecdsa;

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

                hpke = new HPKE(HPKE.mode_base, HPKE.kem_P521_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256);
                break;

            case MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
                kdf = new HKDF(new SHA512Digest());
                digest = new SHA512Digest();
                signer = new Ed448Signer(new byte[0]);
                sigAlgo = ed448;

                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_CHACHA20_POLY1305);
                break;

            default:
                throw new IllegalArgumentException("Unsupported ciphersuite: " + suite);
        }
        short aeadId = hpke.getAeadId();
        aead = new AEAD(aeadId);

    }

    public byte[] serializeSignaturePublicKey(AsymmetricKeyParameter key)
    {

        switch (sigAlgo)
        {
            case ecdsa:
                return ((ECPublicKeyParameters)key).getQ().getEncoded(false);
            case ed448:
                return ((Ed448PublicKeyParameters)key).getEncoded();
            case ed25519:
                return ((Ed25519PublicKeyParameters)key).getEncoded();
            default:
                throw new IllegalStateException("invalid sig algorithm");
        }
    }
    public AsymmetricKeyParameter deserializeSignaturePrivateKey(byte[] priv)
    {
        switch (sigAlgo)
        {
            case ecdsa:
                BigInteger d = new BigInteger(1, priv);
                return new ECPrivateKeyParameters(d, domainParams);
            case ed25519:
                return new Ed25519PrivateKeyParameters(priv);
            case ed448:
               return new Ed448PrivateKeyParameters(priv);
            default:
                throw new IllegalStateException("invalid sig algorithm");
        }
    }

    public AsymmetricKeyParameter getSignaturePublicKey(AsymmetricKeyParameter priv)
    {
        switch (sigAlgo)
        {
            case ecdsa:
                ECPoint Q = new FixedPointCombMultiplier().multiply(domainParams.getG(), ((ECPrivateKeyParameters)priv).getD());
                return new ECPublicKeyParameters(Q, domainParams);
            case ed25519:
                return ((Ed25519PrivateKeyParameters)priv).generatePublicKey();
            case ed448:
                return ((Ed448PrivateKeyParameters)priv).generatePublicKey();
            default:
                return null;
        }
    }
    public byte[] signWithLabel(byte[] priv, String label, byte[] content) throws IOException, CryptoException
    {
        GenericContent signContent = new GenericContent(label, content);
        byte[] signContentBytes = MLSOutputStream.encode(signContent);
        switch (sigAlgo)
        {
            case ecdsa:
                BigInteger d = new BigInteger(1, priv);
                signer.init(true, new ECPrivateKeyParameters(d, domainParams));
                break;
            case ed25519:
                signer.init(true, new Ed25519PrivateKeyParameters(priv));
                break;
            case ed448:
                signer.init(true, new Ed448PrivateKeyParameters(priv));
                break;
        }
        signer.update(signContentBytes, 0, signContentBytes.length);
        return signer.generateSignature();

    }
    public boolean verifyWithLabel(byte[] pub, String label, byte[] content, byte[] signature) throws IOException
    {
        GenericContent signContent = new GenericContent(label, content);
        byte[] signContentBytes = MLSOutputStream.encode(signContent);
        switch (sigAlgo)
        {
            case ecdsa:
                ECPoint G = domainParams.getCurve().decodePoint(pub);
                signer.init(false, new ECPublicKeyParameters(G, domainParams));
                break;
            case ed25519:
                signer.init(false, new Ed25519PublicKeyParameters(pub));
                break;
            case ed448:
                signer.init(false, new Ed448PublicKeyParameters(pub));
                break;
        }
        signer.update(signContentBytes, 0, signContentBytes.length);
        return signer.verifySignature(signature);
    }
    public byte[] refHash(byte[] value, String label) throws IOException
    {
        RefHash refhash = new RefHash(label.getBytes(StandardCharsets.UTF_8), value);
        byte[] refhashBytes = MLSOutputStream.encode(refhash);
//            return expand(out, getHashLength());
        byte[] out = new byte[getKDF().getHashLength()];
        digest.update(refhashBytes, 0, refhashBytes.length);
        digest.doFinal(out, 0);
        return out;
    }
    public byte[] hash(byte[] value) throws IOException
    {
        byte[] out = new byte[getKDF().getHashLength()];
        digest.update(value, 0, value.length);
        digest.doFinal(out, 0);
        return out;
    }

    public byte[] decryptWithLabel(byte[] priv, String label, byte[] context, byte[] kem_output, byte[] ciphertext) throws IOException, InvalidCipherTextException
    {
        GenericContent encryptContext = new GenericContent(label, context);
        byte[] encryptContextBytes = MLSOutputStream.encode(encryptContext);
        AsymmetricKeyParameter privKey;
        AsymmetricKeyParameter pubKey;
        AsymmetricCipherKeyPair kp;
        switch (sigAlgo)
        {
            case ecdsa:
                BigInteger d = new BigInteger(1, priv);
                privKey = new ECPrivateKeyParameters(d, domainParams);
                pubKey = new ECPublicKeyParameters(domainParams.getG().multiply(d), domainParams);
                break;
            case ed25519:
                privKey = new X25519PrivateKeyParameters(priv);
                pubKey = ((X25519PrivateKeyParameters)privKey).generatePublicKey();
                break;
            case ed448:
                privKey = new X448PrivateKeyParameters(priv);
                pubKey = ((X448PrivateKeyParameters)privKey).generatePublicKey();
                break;
            default:
                throw new IllegalStateException("Unknown mode");
        }
        kp = new AsymmetricCipherKeyPair(pubKey, privKey);
        return hpke.open(kem_output, kp, encryptContextBytes, "".getBytes(), ciphertext, null, null, null);
    }
    public byte[][] encryptWithLabel(byte[] pub, String label, byte[] context, byte[] plaintext) throws IOException, InvalidCipherTextException
    {
        GenericContent encryptContext = new GenericContent(label, context);
        byte[] encryptContextBytes = MLSOutputStream.encode(encryptContext);

        AsymmetricKeyParameter pubKey;
        switch (sigAlgo)
        {
            case ecdsa:
                ECPoint G = domainParams.getCurve().decodePoint(pub);
                pubKey = new ECPublicKeyParameters(G, domainParams);
                break;
            case ed25519:
                pubKey = new X25519PublicKeyParameters(pub);
                break;
            case ed448:
                pubKey = new X448PublicKeyParameters(pub);
                break;
            default:
                throw new IllegalStateException("Unknown mode");
        }
        return hpke.seal(pubKey, encryptContextBytes, "".getBytes(), plaintext, null, null, null);
    }

    public KDF getKDF() {
        return kdf;
    }

    public AEAD getAEAD() { return aead; }

    public HPKE getHPKE() { return hpke; }
}
