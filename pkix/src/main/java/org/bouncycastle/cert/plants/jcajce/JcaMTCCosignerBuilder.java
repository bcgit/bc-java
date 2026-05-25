package org.bouncycastle.cert.plants.jcajce;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.ECKey;

import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

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
 * <p>Callers who need to override the detected algorithm string can construct
 * {@link JcaMTCCosigner} directly.</p>
 */
public class JcaMTCCosignerBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcaMTCCosignerBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);
        return this;
    }

    public JcaMTCCosignerBuilder setProvider(Provider provider)
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
        return new JcaMTCCosigner(cosignerId, detectAlgorithm(privateKey), privateKey, helper);
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
