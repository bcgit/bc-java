package org.bouncycastle.cert.plants.bc;

import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.cert.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

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

    public BcMTCSignatureVerifier(String algorithm, AsymmetricKeyParameter publicKey)
    {
        if (MTCSignatureAlgorithm.ED25519.equals(algorithm)
            && !(publicKey instanceof Ed25519PublicKeyParameters))
        {
            throw new IllegalArgumentException("Public key not Ed25519");
        }
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public boolean verify(byte[] cosignedMessage, byte[] signature)
    {
        Signer signer = BcMTCSigners.createSigner(algorithm);
        signer.init(false, publicKey);
        signer.update(cosignedMessage, 0, cosignedMessage.length);
        return signer.verifySignature(signature);
    }
}
