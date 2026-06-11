package org.bouncycastle.cert.plants.bc;

import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAKeyParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/**
 * Shared algorithm-string to lightweight {@link Signer} dispatch for the
 * MTC signature algorithms enumerated in Section 6.1 of
 * draft-ietf-plants-merkle-tree-certs.
 */
final class BcMTCSigners
{
    private BcMTCSigners()
    {
    }

    static Signer createSigner(String algorithm)
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

    /**
     * Detects the MTC signature algorithm string from a lightweight key (public
     * or private) based on the field-size convention used across the BC-side
     * cosigner and verifier bindings.
     *
     * <ul>
     *   <li>{@link ECKeyParameters} on a 256-bit field &rarr; {@code ECDSA-P256-SHA256}</li>
     *   <li>{@link ECKeyParameters} on a 384-bit field &rarr; {@code ECDSA-P384-SHA384}</li>
     *   <li>{@link Ed25519PublicKeyParameters} / {@link Ed25519PrivateKeyParameters} &rarr; {@code Ed25519}</li>
     *   <li>{@link MLDSAKeyParameters} &rarr; {@code ML-DSA-44} / {@code ML-DSA-65} /
     *       {@code ML-DSA-87} per the key's parameter set; the pre-hash
     *       ({@code -with-sha512}) parameter sets are rejected — the MTC
     *       cosigner algorithms are pure ML-DSA.</li>
     * </ul>
     *
     * @throws IllegalArgumentException if the key type or parameter set is unsupported
     */
    static String detectAlgorithm(AsymmetricKeyParameter key)
    {
        if (key instanceof ECKeyParameters)
        {
            int fieldSize = ((ECKeyParameters)key).getParameters().getCurve().getFieldSize();
            if (fieldSize == 256)
            {
                return MTCSignatureAlgorithm.ECDSA_P256_SHA256;
            }
            if (fieldSize == 384)
            {
                return MTCSignatureAlgorithm.ECDSA_P384_SHA384;
            }
            throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        }
        if (key instanceof Ed25519PublicKeyParameters || key instanceof Ed25519PrivateKeyParameters)
        {
            return MTCSignatureAlgorithm.ED25519;
        }
        if (key instanceof MLDSAKeyParameters)
        {
            MLDSAParameters params = ((MLDSAKeyParameters)key).getParameters();
            if (MLDSAParameters.ml_dsa_44 == params)
            {
                return MTCSignatureAlgorithm.ML_DSA_44;
            }
            if (MLDSAParameters.ml_dsa_65 == params)
            {
                return MTCSignatureAlgorithm.ML_DSA_65;
            }
            if (MLDSAParameters.ml_dsa_87 == params)
            {
                return MTCSignatureAlgorithm.ML_DSA_87;
            }
            throw new IllegalArgumentException("Unsupported ML-DSA parameter set: " + params.getName());
        }
        throw new IllegalArgumentException("Unsupported key type: " + key.getClass().getName());
    }
}
