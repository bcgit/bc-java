package org.bouncycastle.mls.crypto.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
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
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.MlsSigner;
import org.bouncycastle.util.encoders.Hex;

public class BcMlsSigner
    implements MlsSigner
{
    Signer signer;
    ECDomainParameters domainParams;
    int sigID;

    public BcMlsSigner(int sigID)
    {
        this.sigID = sigID;

        ECCurve curve;
        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
            signer = new DSADigestSigner(new ECDSASigner(), new SHA256Digest());
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
            break;
        case ecdsa_secp521r1_sha512:
            signer = new DSADigestSigner(new ECDSASigner(), new SHA512Digest());
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
            break;
        case ecdsa_secp384r1_sha384:
            signer = new DSADigestSigner(new ECDSASigner(), new SHA384Digest());
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
            break;
        case ed25519:
            signer = new Ed25519Signer();
            break;
        case ed448:
            signer = new Ed448Signer(new byte[0]);
            break;
        }
    }

    public AsymmetricCipherKeyPair generateSignatureKeyPair()
    {
        SecureRandom random = new SecureRandom();
        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
        case ecdsa_secp521r1_sha512:
        case ecdsa_secp384r1_sha384:
            ECKeyPairGenerator pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(
                domainParams,
                random);
            pGen.init(genParam);
            return pGen.generateKeyPair();
        case ed448:
            Ed448KeyPairGenerator kpg448 = new Ed448KeyPairGenerator();
            kpg448.init(new Ed448KeyGenerationParameters(random));
            return kpg448.generateKeyPair();

        case ed25519:
            Ed25519KeyPairGenerator kpg25519 = new Ed25519KeyPairGenerator();
            kpg25519.init(new Ed25519KeyGenerationParameters(random));
            return kpg25519.generateKeyPair();
        default:
            throw new IllegalStateException("invalid sig algorithm");
        }
    }

    public byte[] serializePublicKey(AsymmetricKeyParameter key)
    {
        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
        case ecdsa_secp521r1_sha512:
        case ecdsa_secp384r1_sha384:
            return ((ECPublicKeyParameters)key).getQ().getEncoded(false);
        case ed448:
            return ((Ed448PublicKeyParameters)key).getEncoded();
        case ed25519:
            return ((Ed25519PublicKeyParameters)key).getEncoded();
        default:
            throw new IllegalStateException("invalid sig algorithm");
        }
    }

    public byte[] serializePrivateKey(AsymmetricKeyParameter key)
    {

        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
        case ecdsa_secp521r1_sha512:
        case ecdsa_secp384r1_sha384:
            return ((ECPrivateKeyParameters)key).getD().toByteArray();
        case ed448:
            return ((Ed448PrivateKeyParameters)key).getEncoded();
        case ed25519:
            return ((Ed25519PrivateKeyParameters)key).getEncoded();
        default:
            throw new IllegalStateException("invalid sig algorithm");
        }
    }

    public AsymmetricKeyParameter deserializePublicKey(byte[] pub)
    {
        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
        case ecdsa_secp521r1_sha512:
        case ecdsa_secp384r1_sha384:
            ECPoint G = domainParams.getCurve().decodePoint(pub);
            return new ECPublicKeyParameters(G, domainParams);
        case ed25519:
            return new X25519PublicKeyParameters(pub);
        case ed448:
            return new X448PublicKeyParameters(pub);
        default:
            throw new IllegalStateException("Unknown mode");
        }
    }

    public AsymmetricCipherKeyPair deserializePrivateKey(byte[] priv)
    {
        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
        case ecdsa_secp521r1_sha512:
        case ecdsa_secp384r1_sha384:
            BigInteger d = new BigInteger(1, priv);
            ECPrivateKeyParameters ec = new ECPrivateKeyParameters(d, domainParams);

            ECPoint Q = new FixedPointCombMultiplier().multiply(domainParams.getG(), ec.getD());
            return new AsymmetricCipherKeyPair(new ECPublicKeyParameters(Q, domainParams), ec);
        case ed25519:
            Ed25519PrivateKeyParameters ed25519 = new Ed25519PrivateKeyParameters(priv);
            return new AsymmetricCipherKeyPair(ed25519.generatePublicKey(), ed25519);
        case ed448:
            Ed448PrivateKeyParameters ed448 = new Ed448PrivateKeyParameters(priv);
            return new AsymmetricCipherKeyPair(ed448.generatePublicKey(), ed448);
        default:
            throw new IllegalStateException("invalid sig algorithm");
        }
    }

    public byte[] signWithLabel(byte[] priv, String label, byte[] content)
        throws IOException, CryptoException
    {
        MlsCipherSuite.GenericContent signContent = new MlsCipherSuite.GenericContent(label, content);
        byte[] signContentBytes = MLSOutputStream.encode(signContent);
        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
        case ecdsa_secp521r1_sha512:
        case ecdsa_secp384r1_sha384:
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

    public boolean verifyWithLabel(byte[] pub, String label, byte[] content, byte[] signature)
        throws IOException
    {
        MlsCipherSuite.GenericContent signContent = new MlsCipherSuite.GenericContent(label, content);
        byte[] signContentBytes = MLSOutputStream.encode(signContent);
        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
        case ecdsa_secp521r1_sha512:
        case ecdsa_secp384r1_sha384:
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
}
