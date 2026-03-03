package org.bouncycastle.crypto.plants;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Verifies cosignatures over MTCSubtrees as defined in draft-ietf-plants-merkle-tree-certs,
 * Section 5.4.1.
 */
public class MTCSignatureVerifier
{
    /**
     * The fixed label for subtree signatures (16 bytes).
     */
    private static final byte[] SUBTREE_LABEL = new byte[]{
        'm', 't', 'c', '-', 's', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', '\n', 0
    };

    /**
     * Verifies a cosignature.
     *
     * @param logId       DER-encoded RELATIVE-OID of the log (without length prefix)
     * @param start       subtree start index
     * @param end         subtree end index
     * @param subtreeHash hash of the subtree (size determined by the log's hash function)
     * @param cosignerId  DER-encoded RELATIVE-OID of the cosigner (without length prefix)
     * @param signature   the signature bytes (as produced by the algorithm's standard encoding)
     * @param publicKey   the cosigner's public key (must match the algorithm)
     * @param algorithm   algorithm identifier, one of:
     *                    "ECDSA-P256-SHA256", "ECDSA-P384-SHA384", "Ed25519",
     *                    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
     * @return true if the signature is valid, false otherwise
     * @throws IllegalArgumentException if the algorithm is unsupported or parameters are invalid
     */
    public static boolean verify(
        byte[] logId,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId,
        byte[] signature,
        AsymmetricKeyParameter publicKey,
        String algorithm)
    {
        // Build the signed data
        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);

        // Obtain a Signer for the given algorithm
        Signer signer = createSigner(algorithm, publicKey);

        // Initialize for verification
        signer.init(false, publicKey);

        // Feed the signed data
        signer.update(signedData, 0, signedData.length);

        // Verify
        return signer.verifySignature(signature);
    }

    /**
     * Constructs the MTCSubtreeSignatureInput bytes as per Section 5.4.1.
     *
     * @param logId       DER-encoded RELATIVE-OID of the log (without length prefix)
     * @param start       start index
     * @param end         end index
     * @param subtreeHash subtree hash
     * @param cosignerId  DER-encoded RELATIVE-OID of the cosigner (without length prefix)
     * @return the byte array to be signed
     */
    private static byte[] buildSignatureInput(
        byte[] logId,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId)
    {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
        {
            // 1. Fixed label
            baos.write(SUBTREE_LABEL);

            // 2. cosigner_id (variable-length, length prefixed)
            writeOpaque(baos, cosignerId);

            // 3. MTCSubtree structure
            //    log_id (variable-length, length prefixed)
            writeOpaque(baos, logId);
            //    start (uint64, big-endian)
            writeUint64(baos, start);
            //    end (uint64, big-endian)
            writeUint64(baos, end);
            //    hash (fixed-length, no length prefix)
            baos.write(subtreeHash);

            return baos.toByteArray();
        }
        catch (IOException e)
        {
            // ByteArrayOutputStream does not throw IOException, but we satisfy the try-with-resources
            throw new RuntimeException("Unexpected IO error", e);
        }
    }

    /**
     * Writes an opaque vector (length-prefixed with a single byte).
     */
    private static void writeOpaque(ByteArrayOutputStream baos, byte[] data)
    {
        if (data.length < 1 || data.length > 255)
        {
            throw new IllegalArgumentException("TrustAnchorID length must be 1..255 bytes");
        }
        baos.write((byte)data.length);
        baos.write(data, 0, data.length);
    }

    /**
     * Writes a 64-bit integer in big-endian order.
     */
    private static void writeUint64(ByteArrayOutputStream baos, long value)
    {
        baos.write((byte)(value >>> 56));
        baos.write((byte)(value >>> 48));
        baos.write((byte)(value >>> 40));
        baos.write((byte)(value >>> 32));
        baos.write((byte)(value >>> 24));
        baos.write((byte)(value >>> 16));
        baos.write((byte)(value >>> 8));
        baos.write((byte)value);
    }

    /**
     * Creates a Bouncy Castle Signer for the given algorithm and public key.
     */
    private static Signer createSigner(String algorithm, AsymmetricKeyParameter publicKey)
    {
        switch (algorithm)
        {
        case "ECDSA-P256-SHA256":
            // Deterministic ECDSA (RFC 6979) with SHA-256 and plain (r||s) encoding
            return new DSADigestSigner(
                new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest())),
                new SHA256Digest(),
                PlainDSAEncoding.INSTANCE
            );
        case "ECDSA-P384-SHA384":
            return new DSADigestSigner(
                new ECDSASigner(new HMacDSAKCalculator(new SHA384Digest())),
                new SHA384Digest(),
                PlainDSAEncoding.INSTANCE
            );
        case "Ed25519":
            if (!(publicKey instanceof Ed25519PublicKeyParameters))
            {
                throw new IllegalArgumentException("Public key not Ed25519");
            }
            return new Ed25519Signer();
        case "ML-DSA-44":
        case "ML-DSA-65":
        case "ML-DSA-87":
            // Assuming Bouncy Castle provides MLDSASigner for these parameter sets
            // The actual class name may vary; adapt as needed.
            return new MLDSASigner(); // Placeholder – replace with actual ML-DSA signer
        default:
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }
}