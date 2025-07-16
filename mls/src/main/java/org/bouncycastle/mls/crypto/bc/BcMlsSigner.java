package org.bouncycastle.mls.crypto.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
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
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
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
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.MlsSigner;

public class BcMlsSigner
    implements MlsSigner
{
    Signer signer;
    ECNamedDomainParameters domainParams;
    int sigID;

    public BcMlsSigner(int sigID)
    {
        this.sigID = sigID;

        switch (sigID)
        {
        case ecdsa_secp256r1_sha256:
            signer = new DSADigestSigner(new ECDSASigner(), new SHA256Digest());
            domainParams = ECNamedDomainParameters.lookup(SECObjectIdentifiers.secp256r1);
            break;
        case ecdsa_secp521r1_sha512:
            signer = new DSADigestSigner(new ECDSASigner(), new SHA512Digest());
            domainParams = ECNamedDomainParameters.lookup(SECObjectIdentifiers.secp521r1);
            break;
        case ecdsa_secp384r1_sha384:
            signer = new DSADigestSigner(new ECDSASigner(), new SHA384Digest());
            domainParams = ECNamedDomainParameters.lookup(SECObjectIdentifiers.secp384r1);
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
            pGen.init(new ECKeyGenerationParameters(domainParams, random));
            return pGen.generateKeyPair();
        case ed25519:
            Ed25519KeyPairGenerator kpg25519 = new Ed25519KeyPairGenerator();
            kpg25519.init(new Ed25519KeyGenerationParameters(random));
            return kpg25519.generateKeyPair();
        case ed448:
            Ed448KeyPairGenerator kpg448 = new Ed448KeyPairGenerator();
            kpg448.init(new Ed448KeyGenerationParameters(random));
            return kpg448.generateKeyPair();
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
        case ed25519:
            return ((Ed25519PublicKeyParameters)key).getEncoded();
        case ed448:
            return ((Ed448PublicKeyParameters)key).getEncoded();
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
        case ed25519:
            return ((Ed25519PrivateKeyParameters)key).getEncoded();
        case ed448:
            return ((Ed448PrivateKeyParameters)key).getEncoded();
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
