package org.bouncycastle.cert.plants.bc;

import java.io.OutputStream;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
    /**
     * Placeholder algorithm identifier returned by {@link #getAlgorithmIdentifier()}.
     * MTC's cosigner signature scheme is identified at the MTCProof / cert level
     * by {@code id-alg-mtcProof}; the underlying cosigner-specific signature
     * algorithm (Ed25519, plain-ECDSA, ML-DSA-XX) is bound at construction and
     * not advertised via this AlgorithmIdentifier.
     */
    private static final AlgorithmIdentifier MTC_SIG_ALG =
        new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);

    private final AsymmetricKeyParameter publicKey;
    private final String algorithm;

    private Signer activeSigner;

    public BcMTCSignatureVerifier(AsymmetricKeyParameter publicKey, String algorithm)
    {
        if (MTCSignatureAlgorithm.ED25519.equals(algorithm)
            && !(publicKey instanceof Ed25519PublicKeyParameters))
        {
            throw new IllegalArgumentException("Public key not Ed25519");
        }
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return MTC_SIG_ALG;
    }

    public OutputStream getOutputStream()
    {
        final Signer signer = BcMTCSigners.createSigner(algorithm);
        signer.init(false, publicKey);
        this.activeSigner = signer;
        return new OutputStream()
        {
            public void write(int b)
            {
                signer.update((byte)b);
            }

            public void write(byte[] buf, int off, int len)
            {
                signer.update(buf, off, len);
            }
        };
    }

    public boolean verify(byte[] expected)
    {
        if (activeSigner == null)
        {
            throw new IllegalStateException("getOutputStream() must be called before verify()");
        }
        return activeSigner.verifySignature(expected);
    }
}
