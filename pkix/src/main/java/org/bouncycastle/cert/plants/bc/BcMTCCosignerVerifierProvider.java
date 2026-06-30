package org.bouncycastle.cert.plants.bc;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
 * {@link BcMTCSignatureVerifier}, auto-detecting the draft algorithm
 * identifier from the key type:</p>
 * <ul>
 *   <li>{@link ECPublicKeyParameters} with a 256-bit field &rarr; {@code ECDSA-P256-SHA256}</li>
 *   <li>{@link ECPublicKeyParameters} with a 384-bit field &rarr; {@code ECDSA-P384-SHA384}</li>
 *   <li>{@link Ed25519PublicKeyParameters} &rarr; {@code Ed25519}</li>
 *   <li>{@link MLDSAPublicKeyParameters} &rarr; {@code ML-DSA-44} / {@code ML-DSA-65} /
 *       {@code ML-DSA-87} per the key's parameter set</li>
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

    /**
     * Convenience factory for the single-cosigner case — wraps
     * {@code Builder().addCosigner(cosignerId, verifier).build()}. Suitable
     * when the relying party trusts exactly one cosigner (e.g. the CA itself,
     * per Section 5.3 of draft-ietf-plants-merkle-tree-certs).
     */
    public static BcMTCCosignerVerifierProvider singleCosigner(
        byte[] cosignerId, MTCSignatureVerifier verifier)
    {
        return new Builder().addCosigner(cosignerId, verifier).build();
    }

    /**
     * Convenience factory for the single-cosigner case taking a lightweight
     * public key; the draft algorithm identifier is detected from the key type.
     *
     * @throws IllegalArgumentException if the public key type is unsupported
     */
    public static BcMTCCosignerVerifierProvider singleCosigner(
        byte[] cosignerId, AsymmetricKeyParameter publicKey)
    {
        return new Builder().addCosigner(cosignerId, publicKey).build();
    }

    public MTCCosignerVerifier get(byte[] cosignerId)
    {
        final MTCSignatureVerifier verifier = cosigners.get(new ByteArrayKey(cosignerId));
        if (verifier == null)
        {
            return null;
        }
        final byte[] boundCosignerId = cosignerId.clone();
        return new MTCCosignerVerifier()
        {
            private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

            public byte[] getCosignerId()
            {
                return boundCosignerId.clone();
            }

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
            }

            public OutputStream getOutputStream()
            {
                buf.reset();
                return buf;
            }

            public boolean verify(byte[] expected)
            {
                return verifier.verify(buf.toByteArray(), expected);
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
         * Register a cosigner with a lightweight public key; the draft
         * algorithm identifier is detected from the key type.
         *
         * @throws IllegalArgumentException if the public key type is unsupported
         */
        public Builder addCosigner(byte[] cosignerId, AsymmetricKeyParameter publicKey)
        {
            return addCosigner(cosignerId, new BcMTCSignatureVerifier(BcMTCSigners.detectAlgorithm(publicKey), publicKey));
        }

        public BcMTCCosignerVerifierProvider build()
        {
            return new BcMTCCosignerVerifierProvider(new HashMap<ByteArrayKey, MTCSignatureVerifier>(cosigners));
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
