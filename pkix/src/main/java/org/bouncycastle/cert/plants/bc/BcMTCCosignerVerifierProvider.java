package org.bouncycastle.cert.plants.bc;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.cert.plants.MTCCosignerVerifier;
import org.bouncycastle.cert.plants.MTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Lightweight-side {@link MTCCosignerVerifierProvider} that holds a table of
 * cosigner trust anchor IDs mapped to {@link MTCSignatureVerifier} instances.
 *
 * <p>The convenience {@link Builder#addCosigner(byte[], AsymmetricKeyParameter)}
 * overload wraps a lightweight {@link AsymmetricKeyParameter} in a
 * {@link BcMTCSignatureVerifier}, auto-detecting the draft-04 algorithm
 * identifier from the key type:</p>
 * <ul>
 *   <li>{@link ECPublicKeyParameters} with a 256-bit field &rarr; {@code ECDSA-P256-SHA256}</li>
 *   <li>{@link ECPublicKeyParameters} with a 384-bit field &rarr; {@code ECDSA-P384-SHA384}</li>
 *   <li>{@link Ed25519PublicKeyParameters} &rarr; {@code Ed25519}</li>
 *   <li>{@link MLDSAPublicKeyParameters} &rarr; {@code ML-DSA-65}</li>
 * </ul>
 *
 * <p>Callers needing a different algorithm string for the same key type, or a
 * key flavour from another module (e.g. a JCA {@code java.security.PublicKey}
 * wrapped in {@code org.bouncycastle.cert.plants.jcajce.JcaMTCSignatureVerifier}),
 * can use {@link Builder#addCosigner(byte[], MTCSignatureVerifier)} directly.</p>
 */
public class BcMTCCosignerVerifierProvider
    implements MTCCosignerVerifierProvider
{
    private final Map<ByteArrayKey, MTCSignatureVerifier> cosigners;

    private BcMTCCosignerVerifierProvider(Map<ByteArrayKey, MTCSignatureVerifier> cosigners)
    {
        this.cosigners = cosigners;
    }

    public MTCCosignerVerifier get(byte[] cosignerId)
    {
        final MTCSignatureVerifier verifier = cosigners.get(new ByteArrayKey(cosignerId));
        if (verifier == null)
        {
            return null;
        }
        return new MTCCosignerVerifier()
        {
            public boolean verify(byte[] cosignedMessage, byte[] signature)
            {
                return verifier.verify(cosignedMessage, signature);
            }
        };
    }

    /**
     * Builder for {@link BcMTCCosignerVerifierProvider}. Cosigner trust anchor
     * IDs are the binary form per Section 3 of draft-ietf-tls-trust-anchor-ids
     * (the base-128 OID-component bytes, without the ASN.1 RELATIVE-OID tag).
     */
    public static class Builder
    {
        private final Map<ByteArrayKey, MTCSignatureVerifier> cosigners
            = new HashMap<ByteArrayKey, MTCSignatureVerifier>();

        /**
         * Register a cosigner with a pre-built signature verifier (either a
         * {@link BcMTCSignatureVerifier} or any other {@link MTCSignatureVerifier}
         * implementation such as
         * {@code org.bouncycastle.cert.plants.jcajce.JcaMTCSignatureVerifier}).
         */
        public Builder addCosigner(byte[] cosignerId, MTCSignatureVerifier verifier)
        {
            cosigners.put(new ByteArrayKey(cosignerId), verifier);
            return this;
        }

        /**
         * Register a cosigner with a lightweight public key; the draft-04
         * algorithm identifier is detected from the key type.
         *
         * @throws IllegalArgumentException if the public key type is unsupported
         */
        public Builder addCosigner(byte[] cosignerId, AsymmetricKeyParameter publicKey)
        {
            return addCosigner(cosignerId, new BcMTCSignatureVerifier(publicKey, detectAlgorithm(publicKey)));
        }

        public BcMTCCosignerVerifierProvider build()
        {
            return new BcMTCCosignerVerifierProvider(new HashMap<ByteArrayKey, MTCSignatureVerifier>(cosigners));
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
        if (key instanceof MLDSAPublicKeyParameters)
        {
            return "ML-DSA-65";
        }
        throw new IllegalArgumentException("Unsupported public key type: " + key.getClass().getName());
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
