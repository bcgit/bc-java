package org.bouncycastle.cert.plants.bc;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.cert.plants.MTCCosignerVerifier;
import org.bouncycastle.cert.plants.MTCCosignerVerifierProvider;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.plants.MTCSignatureVerifier;
import org.bouncycastle.util.Arrays;

/**
 * Lightweight-side {@link MTCCosignerVerifierProvider} that holds a table of
 * cosigner trust anchor IDs mapped to {@link AsymmetricKeyParameter} public
 * keys.
 *
 * <p>Construct via {@link Builder}; each cosigner's signature algorithm is
 * derived from its key type (EC field size, Ed25519, ML-DSA) at build time.
 * The returned {@link MTCCosignerVerifier} instances delegate to
 * {@link MTCSignatureVerifier} for the actual signature primitive.</p>
 *
 * <p>Supported key types and the resulting algorithm identifiers:</p>
 * <ul>
 *   <li>{@link ECPublicKeyParameters} with a 256-bit field &rarr; {@code ECDSA-P256-SHA256}</li>
 *   <li>{@link ECPublicKeyParameters} with a 384-bit field &rarr; {@code ECDSA-P384-SHA384}</li>
 *   <li>{@link Ed25519PublicKeyParameters} &rarr; {@code Ed25519}</li>
 *   <li>{@code MLDSAPublicKeyParameters} (detected by class name to avoid a
 *       hard {@code pqc} dependency at compile time) &rarr; {@code ML-DSA-65}</li>
 * </ul>
 */
public class BcMTCCosignerVerifierProvider
    implements MTCCosignerVerifierProvider
{
    private final Map<ByteArrayKey, ResolvedCosigner> cosigners;

    private BcMTCCosignerVerifierProvider(Map<ByteArrayKey, ResolvedCosigner> cosigners)
    {
        this.cosigners = cosigners;
    }

    public MTCCosignerVerifier get(byte[] cosignerId)
    {
        ResolvedCosigner resolved = cosigners.get(new ByteArrayKey(cosignerId));
        if (resolved == null)
        {
            return null;
        }
        return new BcCosignerVerifier(resolved.publicKey, resolved.algorithm);
    }

    /**
     * Builder for {@link BcMTCCosignerVerifierProvider}. Cosigner trust anchor
     * IDs are the binary form per Section 3 of draft-ietf-tls-trust-anchor-ids
     * (the base-128 OID-component bytes, without the ASN.1 RELATIVE-OID tag).
     */
    public static class Builder
    {
        private final Map<ByteArrayKey, ResolvedCosigner> cosigners = new HashMap<ByteArrayKey, ResolvedCosigner>();

        /**
         * Register a cosigner.
         *
         * @param cosignerId the binary trust anchor ID
         * @param publicKey  the cosigner's public key
         * @throws IllegalArgumentException if the public key type is unsupported
         */
        public Builder addCosigner(byte[] cosignerId, AsymmetricKeyParameter publicKey)
        {
            String algorithm = detectAlgorithm(publicKey);
            cosigners.put(new ByteArrayKey(cosignerId), new ResolvedCosigner(publicKey, algorithm));
            return this;
        }

        public BcMTCCosignerVerifierProvider build()
        {
            return new BcMTCCosignerVerifierProvider(new HashMap<ByteArrayKey, ResolvedCosigner>(cosigners));
        }
    }

    private static String detectAlgorithm(AsymmetricKeyParameter key)
    {
        if (key instanceof ECPublicKeyParameters)
        {
            int fieldSize = ((ECPublicKeyParameters)key).getParameters().getCurve().getFieldSize();
            if (fieldSize == 256)
            {
                return "ECDSA-P256-SHA256";
            }
            if (fieldSize == 384)
            {
                return "ECDSA-P384-SHA384";
            }
            throw new IllegalArgumentException("Unsupported EC field size: " + fieldSize);
        }
        if (key instanceof Ed25519PublicKeyParameters)
        {
            return "Ed25519";
        }
        if (key.getClass().getName().contains("MLDSAPublicKeyParameters"))
        {
            return "ML-DSA-65";
        }
        throw new IllegalArgumentException("Unsupported public key type: " + key.getClass().getName());
    }

    private static class BcCosignerVerifier
        implements MTCCosignerVerifier
    {
        private final AsymmetricKeyParameter publicKey;
        private final String algorithm;

        BcCosignerVerifier(AsymmetricKeyParameter publicKey, String algorithm)
        {
            this.publicKey = publicKey;
            this.algorithm = algorithm;
        }

        public boolean verify(byte[] cosignedMessage, byte[] signature)
            throws IOException
        {
            return MTCSignatureVerifier.verify(cosignedMessage, signature, publicKey, algorithm);
        }
    }

    private static class ResolvedCosigner
    {
        final AsymmetricKeyParameter publicKey;
        final String algorithm;

        ResolvedCosigner(AsymmetricKeyParameter publicKey, String algorithm)
        {
            this.publicKey = publicKey;
            this.algorithm = algorithm;
        }
    }

    private static class ByteArrayKey
    {
        private final byte[] data;

        ByteArrayKey(byte[] data)
        {
            this.data = data.clone();
        }

        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (!(o instanceof ByteArrayKey))
            {
                return false;
            }
            return Arrays.areEqual(this.data, ((ByteArrayKey)o).data);
        }

        public int hashCode()
        {
            return Arrays.hashCode(data);
        }
    }
}
