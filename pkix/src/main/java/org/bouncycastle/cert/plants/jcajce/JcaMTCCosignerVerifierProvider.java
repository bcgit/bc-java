package org.bouncycastle.cert.plants.jcajce;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.plants.MTCCosignerVerifier;
import org.bouncycastle.cert.plants.MTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.cert.plants.MTCSignatureVerifier;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.Arrays;

/**
 * JCA-side {@link MTCCosignerVerifierProvider} that holds a table of cosigner
 * trust anchor IDs mapped to {@link MTCSignatureVerifier} instances.
 *
 * <p>The convenience {@link Builder#addCosigner(byte[], PublicKey)} overload
 * wraps a JCA {@link PublicKey} in a {@link JcaMTCSignatureVerifier},
 * auto-detecting the draft algorithm identifier from the key type:</p>
 * <ul>
 *   <li>{@link ECPublicKey} with a 256-bit field &rarr; {@code ECDSA-P256-SHA256}</li>
 *   <li>{@link ECPublicKey} with a 384-bit field &rarr; {@code ECDSA-P384-SHA384}</li>
 *   <li>{@code getAlgorithm()} equal to {@code "Ed25519"} or {@code "EdDSA"} &rarr; {@code Ed25519}</li>
 *   <li>{@code getAlgorithm()} equal to {@code "ML-DSA-44"} / {@code "ML-DSA-65"} / {@code "ML-DSA-87"} &rarr; same string</li>
 * </ul>
 *
 * <p>Callers needing a different algorithm string for the same key type, or a
 * verifier from another module (e.g. a lightweight {@code BcMTCSignatureVerifier}),
 * can use {@link Builder#addCosigner(byte[], MTCSignatureVerifier)} directly.</p>
 */
public class JcaMTCCosignerVerifierProvider
    implements MTCCosignerVerifierProvider
{
    private final Map<ByteArrayKey, MTCSignatureVerifier> cosigners;

    private JcaMTCCosignerVerifierProvider(Map<ByteArrayKey, MTCSignatureVerifier> cosigners)
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
            private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

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
     * Builder for {@link JcaMTCCosignerVerifierProvider}.
     */
    public static class Builder
    {
        private JcaJceHelper helper = new DefaultJcaJceHelper();
        private final Map<ByteArrayKey, MTCSignatureVerifier> cosigners
            = new HashMap<ByteArrayKey, MTCSignatureVerifier>();

        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);
            return this;
        }

        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);
            return this;
        }

        /**
         * Register a cosigner with a pre-built signature verifier.
         */
        public Builder addCosigner(byte[] cosignerId, MTCSignatureVerifier verifier)
        {
            cosigners.put(new ByteArrayKey(cosignerId), verifier);
            return this;
        }

        /**
         * Register a cosigner with a JCA public key; the draft algorithm
         * identifier is detected from the key type.
         *
         * @throws IllegalArgumentException if the public key type is unsupported
         */
        public Builder addCosigner(byte[] cosignerId, PublicKey publicKey)
        {
            return addCosigner(cosignerId, new JcaMTCSignatureVerifier(publicKey, detectAlgorithm(publicKey), helper));
        }

        public JcaMTCCosignerVerifierProvider build()
        {
            return new JcaMTCCosignerVerifierProvider(new HashMap<ByteArrayKey, MTCSignatureVerifier>(cosigners));
        }
    }

    private static String detectAlgorithm(PublicKey key)
    {
        if (key instanceof ECPublicKey)
        {
            int bits = ((ECPublicKey)key).getParams().getOrder().bitLength();
            if (bits >= 252 && bits <= 256)
            {
                return MTCSignatureAlgorithm.ECDSA_P256_SHA256;
            }
            if (bits >= 380 && bits <= 384)
            {
                return MTCSignatureAlgorithm.ECDSA_P384_SHA384;
            }
            throw new IllegalArgumentException("Unsupported EC field size: " + bits);
        }
        String algName = key.getAlgorithm();
        if ("Ed25519".equals(algName) || "EdDSA".equals(algName))
        {
            return MTCSignatureAlgorithm.ED25519;
        }
        if (MTCSignatureAlgorithm.ML_DSA_44.equals(algName)
            || MTCSignatureAlgorithm.ML_DSA_65.equals(algName)
            || MTCSignatureAlgorithm.ML_DSA_87.equals(algName))
        {
            return algName;
        }
        throw new IllegalArgumentException("Unsupported public key type: " + algName);
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
