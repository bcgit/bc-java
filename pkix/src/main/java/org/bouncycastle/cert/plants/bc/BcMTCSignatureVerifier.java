package org.bouncycastle.cert.plants.bc;

import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.cert.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/**
 * Lightweight implementation of {@link MTCSignatureVerifier}.
 *
 * <p>Bound to an {@link AsymmetricKeyParameter} and one of the algorithm
 * identifiers defined by Section 6.1 of draft-ietf-plants-merkle-tree-certs:
 * {@code "ECDSA-P256-SHA256"}, {@code "ECDSA-P384-SHA384"}, {@code "Ed25519"},
 * {@code "ML-DSA-44"}, {@code "ML-DSA-65"}, {@code "ML-DSA-87"}.</p>
 */
public class BcMTCSignatureVerifier
    implements MTCSignatureVerifier
{
    private final AsymmetricKeyParameter publicKey;
    private final String algorithm;

    public BcMTCSignatureVerifier(AsymmetricKeyParameter publicKey, String algorithm)
    {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }

    public boolean verify(byte[] cosignedMessage, byte[] signature)
    {
        Signer signer = createSigner(algorithm, publicKey);
        signer.init(false, publicKey);
        signer.update(cosignedMessage, 0, cosignedMessage.length);
        return signer.verifySignature(signature);
    }

    private static Signer createSigner(String algorithm, AsymmetricKeyParameter publicKey)
    {
        if (MTCSignatureAlgorithm.ECDSA_P256_SHA256.equals(algorithm))
        {
            return new DSADigestSigner(
                new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest())),
                new SHA256Digest(),
                PlainDSAEncoding.INSTANCE);
        }
        if (MTCSignatureAlgorithm.ECDSA_P384_SHA384.equals(algorithm))
        {
            return new DSADigestSigner(
                new ECDSASigner(new HMacDSAKCalculator(new SHA384Digest())),
                new SHA384Digest(),
                PlainDSAEncoding.INSTANCE);
        }
        if (MTCSignatureAlgorithm.ED25519.equals(algorithm))
        {
            if (!(publicKey instanceof Ed25519PublicKeyParameters))
            {
                throw new IllegalArgumentException("Public key not Ed25519");
            }
            return new Ed25519Signer();
        }
        if (MTCSignatureAlgorithm.ML_DSA_44.equals(algorithm)
            || MTCSignatureAlgorithm.ML_DSA_65.equals(algorithm)
            || MTCSignatureAlgorithm.ML_DSA_87.equals(algorithm))
        {
            return new MLDSASigner();
        }
        throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
    }
}
