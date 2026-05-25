package org.bouncycastle.cert.plants.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

import org.bouncycastle.cert.plants.MTCCosignedMessage;
import org.bouncycastle.cert.plants.MTCCosigner;
import org.bouncycastle.cert.plants.MTCLog;
import org.bouncycastle.cert.plants.MTCSignature;
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
 */
public class JcaMTCCosigner
    implements MTCCosigner
{
    private final byte[] cosignerId;
    private final String algorithm;
    private final PrivateKey privateKey;
    private final JcaJceHelper helper;

    public JcaMTCCosigner(byte[] cosignerId, String algorithm, PrivateKey privateKey)
    {
        this(cosignerId, algorithm, privateKey, new DefaultJcaJceHelper());
    }

    public JcaMTCCosigner(String algorithm, byte[] cosignerId, PrivateKey privateKey, String providerName)
    {
        this(cosignerId, algorithm, privateKey, new NamedJcaJceHelper(providerName));
    }

    public JcaMTCCosigner(byte[] cosignerId, String algorithm, PrivateKey privateKey, Provider provider)
    {
        this(cosignerId, algorithm, privateKey, new ProviderJcaJceHelper(provider));
    }

    public JcaMTCCosigner(byte[] cosignerId, String algorithm, PrivateKey privateKey, JcaJceHelper helper)
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
}
