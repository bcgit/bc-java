package org.bouncycastle.cert.plants.bc;

import java.io.IOException;

import org.bouncycastle.cert.plants.MTCCosignedMessage;
import org.bouncycastle.cert.plants.MTCCosigner;
import org.bouncycastle.cert.plants.MTCLog;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * Lightweight implementation of {@link MTCCosigner} for the MTC signature
 * algorithms enumerated in Section 6.1 of draft-ietf-plants-merkle-tree-certs:
 * {@code "ECDSA-P256-SHA256"}, {@code "ECDSA-P384-SHA384"}, {@code "Ed25519"},
 * {@code "ML-DSA-44"}, {@code "ML-DSA-65"}, {@code "ML-DSA-87"}.
 *
 * <p>Symmetric counterpart of {@link BcMTCSignatureVerifier} — encapsulates
 * the {@link MTCCosignedMessage} encode plus the underlying lightweight
 * {@link Signer} ceremony.</p>
 */
public class BcMTCCosigner
    implements MTCCosigner
{
    private final byte[] cosignerId;
    private final String algorithm;
    private final AsymmetricKeyParameter privateKey;

    /**
     * @param cosignerId binary trust anchor ID of this cosigner — the CA's own
     *                   trust anchor ID when the CA itself cosigns (Section
     *                   5.3); the cosigner's own trust anchor ID otherwise
     * @param privateKey lightweight private key whose type determines the MTC
     *                   signature algorithm (see
     *                   {@link BcMTCSigners#detectAlgorithm})
     */
    public BcMTCCosigner(byte[] cosignerId, AsymmetricKeyParameter privateKey)
    {
        this(BcMTCSigners.detectAlgorithm(privateKey), cosignerId, privateKey);
    }

    /**
     * Override constructor that takes an explicit MTC algorithm string instead
     * of detecting it from the key type. Use when the key's
     * {@link BcMTCSigners#detectAlgorithm key-type dispatch} doesn't apply.
     */
    public BcMTCCosigner(String algorithm, byte[] cosignerId, AsymmetricKeyParameter privateKey)
    {
        this.cosignerId = Arrays.clone(cosignerId);
        this.algorithm = algorithm;
        this.privateKey = privateKey;
    }

    public byte[] getCosignerId()
    {
        return Arrays.clone(cosignerId);
    }

    public MTCSignature cosignSubtree(MTCLog log, byte[] subtreeHash)
        throws IOException
    {
        byte[] msg = MTCCosignedMessage.encode(log, subtreeHash, cosignerId);
        Signer signer = BcMTCSigners.createSigner(algorithm);
        signer.init(true, privateKey);
        signer.update(msg, 0, msg.length);
        try
        {
            return new MTCSignature(cosignerId, signer.generateSignature());
        }
        catch (CryptoException e)
        {
            throw Exceptions.ioException("MTC cosigning failed: " + e.getMessage(), e);
        }
    }
}
