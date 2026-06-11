package org.bouncycastle.cert.plants.jcajce;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.cert.plants.MTCSignatureVerifier;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.Exceptions;

/**
 * JCA-side implementation of {@link MTCSignatureVerifier}.
 *
 * <p>Bound to a {@link PublicKey} and one of the algorithm identifiers defined
 * by Section 6.1 of draft-ietf-plants-merkle-tree-certs:
 * {@code "ECDSA-P256-SHA256"}, {@code "ECDSA-P384-SHA384"}, {@code "Ed25519"},
 * {@code "ML-DSA-44"}, {@code "ML-DSA-65"}, {@code "ML-DSA-87"}.</p>
 *
 * <p>The draft identifiers are mapped to JCA Signature names internally —
 * the plain (r||s) ECDSA encoding used by MTCProof requires
 * {@code SHA256WITHPLAIN-ECDSA} / {@code SHA384WITHPLAIN-ECDSA}, which BC's
 * JCE provider registers (DER-encoded {@code SHA256withECDSA} is wire-incompatible
 * with the MTCProof signature byte format).</p>
 *
 * <p>Instances are created via {@link Builder}.</p>
 */
public class JcaMTCSignatureVerifier
    implements MTCSignatureVerifier
{
    private final PublicKey publicKey;
    private final String algorithm;
    private final JcaJceHelper helper;

    JcaMTCSignatureVerifier(String algorithm, PublicKey publicKey, JcaJceHelper helper)
    {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
        this.helper = helper;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public boolean verify(byte[] cosignedMessage, byte[] signature)
    {
        try
        {
            Signature sig = helper.createSignature(jcaAlgorithm(algorithm));
            sig.initVerify(publicKey);
            sig.update(cosignedMessage);
            return sig.verify(signature);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(
                "unable to verify MTC signature with algorithm " + algorithm + ": " + e.getMessage(), e);
        }
    }

    /**
     * Maps a draft algorithm identifier to the JCA Signature algorithm name.
     */
    static String jcaAlgorithm(String mtcAlgorithm)
    {
        if (MTCSignatureAlgorithm.ECDSA_P256_SHA256.equals(mtcAlgorithm))
        {
            return "SHA256WITHPLAIN-ECDSA";
        }
        if (MTCSignatureAlgorithm.ECDSA_P384_SHA384.equals(mtcAlgorithm))
        {
            return "SHA384WITHPLAIN-ECDSA";
        }
        if (MTCSignatureAlgorithm.ED25519.equals(mtcAlgorithm))
        {
            return "Ed25519";
        }
        if (MTCSignatureAlgorithm.ML_DSA_44.equals(mtcAlgorithm)
            || MTCSignatureAlgorithm.ML_DSA_65.equals(mtcAlgorithm)
            || MTCSignatureAlgorithm.ML_DSA_87.equals(mtcAlgorithm))
        {
            return mtcAlgorithm;
        }
        throw new IllegalArgumentException("Unsupported algorithm: " + mtcAlgorithm);
    }

    /**
     * Detects the MTC signature algorithm string from a JCA public key:
     *
     * <ul>
     *   <li>{@link ECPublicKey} with a 256-bit order &rarr; {@code ECDSA-P256-SHA256}</li>
     *   <li>{@link ECPublicKey} with a 384-bit order &rarr; {@code ECDSA-P384-SHA384}</li>
     *   <li>{@code getAlgorithm()} equal to {@code "Ed25519"} or {@code "EdDSA"} &rarr; {@code Ed25519}</li>
     *   <li>{@code getAlgorithm()} equal to {@code "ML-DSA-44"} / {@code "ML-DSA-65"} /
     *       {@code "ML-DSA-87"} &rarr; same string</li>
     * </ul>
     *
     * @throws IllegalArgumentException if the public key type is unsupported
     */
    static String detectAlgorithm(PublicKey key)
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

    /**
     * Builder for {@link JcaMTCSignatureVerifier}. Selects the JCA provider
     * used to obtain the underlying {@link java.security.Signature} instance;
     * the draft algorithm identifier is either detected from the public key
     * type ({@link #build(PublicKey)} — see {@link #detectAlgorithm}) or
     * supplied explicitly ({@link #build(String, PublicKey)}).
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
         * @param publicKey JCA public key whose type determines the MTC
         *                  signature algorithm string (see {@link #detectAlgorithm})
         * @throws IllegalArgumentException if the public key type is unsupported
         */
        public JcaMTCSignatureVerifier build(PublicKey publicKey)
        {
            return build(detectAlgorithm(publicKey), publicKey);
        }

        /**
         * Explicit-algorithm overload for cases where the key-type detection in
         * {@link #build(PublicKey)} doesn't apply (e.g. a key whose
         * {@code getAlgorithm()} doesn't carry the MTC algorithm name).
         *
         * @param algorithm one of the {@link MTCSignatureAlgorithm} constants
         * @param publicKey JCA public key for {@code algorithm}
         */
        public JcaMTCSignatureVerifier build(String algorithm, PublicKey publicKey)
        {
            return new JcaMTCSignatureVerifier(algorithm, publicKey, helper);
        }
    }
}
