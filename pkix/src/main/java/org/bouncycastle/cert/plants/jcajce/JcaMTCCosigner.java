package org.bouncycastle.cert.plants.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECKey;

import org.bouncycastle.cert.plants.MTCCosignedMessage;
import org.bouncycastle.cert.plants.MTCCosigner;
import org.bouncycastle.cert.plants.MTCLog;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.Arrays;

/**
 * JCA-side implementation of {@link MTCCosigner} for the MTC signature
 * algorithms enumerated in Section 6.1 of draft-ietf-plants-merkle-tree-certs:
 * {@code "ECDSA-P256-SHA256"}, {@code "ECDSA-P384-SHA384"}, {@code "Ed25519"},
 * {@code "ML-DSA-44"}, {@code "ML-DSA-65"}, {@code "ML-DSA-87"}.
 *
 * <p>Symmetric counterpart of {@link JcaMTCSignatureVerifier} — encapsulates
 * the {@link MTCCosignedMessage} encode plus the underlying JCA
 * {@link Signature} ceremony. The draft identifiers are mapped to JCA Signature
 * names internally; the plain (r||s) ECDSA encoding used by MTCProof requires
 * {@code SHA256WITHPLAIN-ECDSA} / {@code SHA384WITHPLAIN-ECDSA}, which BC's
 * JCE provider registers (DER-encoded {@code SHA256withECDSA} is wire-incompatible
 * with the MTCProof signature byte format).</p>
 *
 * <p>Instances are created via {@link Builder}.</p>
 */
public class JcaMTCCosigner
    implements MTCCosigner
{
    private final byte[] cosignerId;
    private final String algorithm;
    private final PrivateKey privateKey;
    private final JcaJceHelper helper;

    private JcaMTCCosigner(String algorithm, byte[] cosignerId, PrivateKey privateKey, JcaJceHelper helper)
    {
        this.cosignerId = Arrays.clone(cosignerId);
        this.algorithm = algorithm;
        this.privateKey = privateKey;
        this.helper = helper;
    }

    public byte[] getCosignerId()
    {
        return Arrays.clone(cosignerId);
    }

    public MTCSignature cosignSubtree(MTCLog log, byte[] subtreeHash)
        throws IOException
    {
        byte[] msg = MTCCosignedMessage.encode(log, subtreeHash, cosignerId);
        try
        {
            Signature sig = helper.createSignature(JcaMTCSignatureVerifier.jcaAlgorithm(algorithm));
            sig.initSign(privateKey);
            sig.update(msg);
            return new MTCSignature(cosignerId, sig.sign());
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException(
                "MTC cosigning failed with algorithm " + algorithm + ": " + e.getMessage(), e);
        }
    }

    /**
     * Builder for {@link JcaMTCCosigner}. Selects the JCA provider used to obtain
     * the underlying {@link java.security.Signature} instance; the draft algorithm
     * identifier is detected from the private key type at {@link #build} time.
     *
     * <ul>
     *   <li>{@link java.security.interfaces.ECPrivateKey} with a 256-bit order
     *       &rarr; {@code ECDSA-P256-SHA256}</li>
     *   <li>{@link java.security.interfaces.ECPrivateKey} with a 384-bit order
     *       &rarr; {@code ECDSA-P384-SHA384}</li>
     *   <li>{@code getAlgorithm()} equal to {@code "Ed25519"} or {@code "EdDSA"}
     *       &rarr; {@code Ed25519}</li>
     *   <li>{@code getAlgorithm()} equal to {@code "ML-DSA-44"} /
     *       {@code "ML-DSA-65"} / {@code "ML-DSA-87"} &rarr; same string</li>
     * </ul>
     *
     * <p>Callers who need to override the detected algorithm string can use the
     * explicit {@link #build(String, byte[], PrivateKey)} overload.</p>
     */
    public static class Builder
    {
        private JcaJceHelper helper = new DefaultJcaJceHelper();

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
         * @param cosignerId binary trust anchor ID of this cosigner — the CA's own
         *                   trust anchor ID when the CA itself cosigns (Section
         *                   5.3); the cosigner's own trust anchor ID otherwise
         * @param privateKey JCA private key whose algorithm determines the MTC
         *                   signature algorithm string (see class javadoc)
         * @throws IllegalArgumentException if the private key type is unsupported
         */
        public JcaMTCCosigner build(byte[] cosignerId, PrivateKey privateKey)
        {
            return build(detectAlgorithm(privateKey), cosignerId, privateKey);
        }

        /**
         * Explicit-algorithm overload for cases where the key-type detection in
         * {@link #build(byte[], PrivateKey)} doesn't apply (e.g. a key whose
         * {@code getAlgorithm()} doesn't carry the MTC algorithm name).
         *
         * @param algorithm  one of the {@link MTCSignatureAlgorithm} constants
         * @param cosignerId binary trust anchor ID of this cosigner — the CA's own
         *                   trust anchor ID when the CA itself cosigns (Section
         *                   5.3); the cosigner's own trust anchor ID otherwise
         * @param privateKey JCA private key for {@code algorithm}
         */
        public JcaMTCCosigner build(String algorithm, byte[] cosignerId, PrivateKey privateKey)
        {
            return new JcaMTCCosigner(algorithm, cosignerId, privateKey, helper);
        }

        private static String detectAlgorithm(PrivateKey key)
        {
            if (key instanceof ECKey)
            {
                int bits = ((ECKey)key).getParams().getOrder().bitLength();
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
            throw new IllegalArgumentException("Unsupported private key type: " + algName);
        }
    }
}
