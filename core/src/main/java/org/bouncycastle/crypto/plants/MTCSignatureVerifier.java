package org.bouncycastle.crypto.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.bouncycastle.asn1.ASN1RelativeOID;
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

/**
 * Verifies cosignatures over a CosignedMessage as defined in
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs-04</a>,
 * Section 5.3.1.
 *
 * <pre>
 * struct {
 *     uint8 label[12] = "subtree/v1\n\0";
 *     opaque cosigner_name&lt;1..2^8-1&gt;;
 *     uint64 timestamp;
 *     opaque log_origin&lt;1..2^8-1&gt;;
 *     uint64 start;
 *     uint64 end;
 *     HashValue subtree_hash;
 * } CosignedMessage;
 * </pre>
 *
 * <p>{@code cosigner_name} and {@code log_origin} are the ASCII strings
 * {@code "oid/1.3.6.1.4.1." + <dotted-decimal trust anchor ID>}. The verifier
 * constructs them from the binary trust anchor IDs supplied by the caller via
 * the BC ASN1RelativeOID conversion.</p>
 */
public class MTCSignatureVerifier
{
    /** The fixed 12-byte label for CosignedMessage: "subtree/v1" + LF + NUL. */
    private static final byte[] SUBTREE_LABEL = new byte[]{
        's', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', (byte)0x0A, (byte)0x00
    };

    /** Fixed ASCII prefix prepended to dotted-decimal trust anchor IDs. */
    private static final byte[] OID_PREFIX = "oid/1.3.6.1.4.1.".getBytes(Charset.forName("US-ASCII"));

    /**
     * Verifies an MTCProof cosignature. Equivalent to a {@link #verify(byte[], long, long, long, byte[], byte[], byte[], AsymmetricKeyParameter, String)}
     * call with {@code timestamp == 0}, which is the only value allowed inside
     * an MTCProof per Section 6.1 of draft-04.
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
        throws IOException
    {
        return verify(logId, 0L, start, end, subtreeHash, cosignerId, signature, publicKey, algorithm);
    }

    /**
     * Verifies a cosignature over a CosignedMessage.
     *
     * @param logId       binary trust anchor ID of the log (the CA's OID prefix
     *                    followed by {@code 0x00} and the base-128 encoding of
     *                    the log number, per Section 5.2)
     * @param timestamp   POSIX timestamp; MUST be zero for MTCProof signatures
     *                    (Section 6.1)
     * @param start       subtree start index
     * @param end         subtree end index
     * @param subtreeHash hash of the subtree
     * @param cosignerId  binary trust anchor ID of the cosigner
     * @param signature   signature bytes
     * @param publicKey   the cosigner's public key
     * @param algorithm   algorithm identifier, one of
     *                    {@code "ECDSA-P256-SHA256"}, {@code "ECDSA-P384-SHA384"},
     *                    {@code "Ed25519"}, {@code "ML-DSA-44"}, {@code "ML-DSA-65"},
     *                    {@code "ML-DSA-87"}
     * @return true if the signature is valid
     */
    public static boolean verify(
        byte[] logId,
        long timestamp,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId,
        byte[] signature,
        AsymmetricKeyParameter publicKey,
        String algorithm)
        throws IOException
    {
        byte[] signedData = buildCosignedMessage(logId, timestamp, start, end, subtreeHash, cosignerId);

        Signer signer = createSigner(algorithm, publicKey);
        signer.init(false, publicKey);
        signer.update(signedData, 0, signedData.length);
        return signer.verifySignature(signature);
    }

    /**
     * Constructs the CosignedMessage bytes per Section 5.3.1 of draft-04.
     */
    static byte[] buildCosignedMessage(
        byte[] logId,
        long timestamp,
        long start,
        long end,
        byte[] subtreeHash,
        byte[] cosignerId)
        throws IOException
    {
        byte[] cosignerName = asciiName(cosignerId);
        byte[] logOrigin = asciiName(logId);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(SUBTREE_LABEL);          // 12 bytes
        writeOpaque1(baos, cosignerName);    // cosigner_name
        writeUint64(baos, timestamp);        // timestamp
        writeOpaque1(baos, logOrigin);       // log_origin
        writeUint64(baos, start);
        writeUint64(baos, end);
        baos.write(subtreeHash);             // fixed-size HashValue
        return baos.toByteArray();
    }

    /**
     * Builds the ASCII name {@code "oid/1.3.6.1.4.1." + dotted-decimal} for a
     * binary trust anchor ID.
     */
    private static byte[] asciiName(byte[] binaryTrustAnchorID)
    {
        String dotted = ASN1RelativeOID.fromContents(binaryTrustAnchorID).getId();
        byte[] dottedBytes = dotted.getBytes(Charset.forName("US-ASCII"));
        byte[] out = new byte[OID_PREFIX.length + dottedBytes.length];
        System.arraycopy(OID_PREFIX, 0, out, 0, OID_PREFIX.length);
        System.arraycopy(dottedBytes, 0, out, OID_PREFIX.length, dottedBytes.length);
        return out;
    }

    private static void writeOpaque1(ByteArrayOutputStream baos, byte[] data)
    {
        if (data.length < 1 || data.length > 255)
        {
            throw new IllegalArgumentException("opaque<1..255> length must be 1..255 bytes, got " + data.length);
        }
        baos.write(data.length);
        baos.write(data, 0, data.length);
    }

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

    private static Signer createSigner(String algorithm, AsymmetricKeyParameter publicKey)
    {
        switch (algorithm)
        {
        case "ECDSA-P256-SHA256":
            return new DSADigestSigner(
                new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest())),
                new SHA256Digest(),
                PlainDSAEncoding.INSTANCE);
        case "ECDSA-P384-SHA384":
            return new DSADigestSigner(
                new ECDSASigner(new HMacDSAKCalculator(new SHA384Digest())),
                new SHA384Digest(),
                PlainDSAEncoding.INSTANCE);
        case "Ed25519":
            if (!(publicKey instanceof Ed25519PublicKeyParameters))
            {
                throw new IllegalArgumentException("Public key not Ed25519");
            }
            return new Ed25519Signer();
        case "ML-DSA-44":
        case "ML-DSA-65":
        case "ML-DSA-87":
            return new MLDSASigner();
        default:
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }
}
