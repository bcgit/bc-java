package org.bouncycastle.cert.plants;

import org.bouncycastle.util.Arrays;

/**
 * A single Merkle Tree certificate log-entry extension, per Section 5.2.1 of
 * draft-ietf-plants-merkle-tree-certs:
 *
 * <pre>
 * struct {
 *     MerkleTreeCertEntryExtensionType extension_type;
 *     opaque extension_data&lt;0..2^16-1&gt;;
 * } MerkleTreeCertEntryExtension;
 * </pre>
 *
 * <p>The {@code extension_type} is a uint16 (the draft assigns no concrete
 * values yet) and {@code extension_data} is opaque<0..65535>. Extensions
 * carried inside a {@link MTCProof} or hashed into a log entry MUST appear
 * in ascending order by {@code extension_type} with no duplicates; the
 * {@link MTCProof} encoder/decoder enforces this.</p>
 */
public final class MerkleTreeCertEntryExtension
{
    private final int extensionType;
    private final byte[] extensionData;

    /**
     * @param extensionType the {@code MerkleTreeCertEntryExtensionType} value (uint16, 0..65535)
     * @param extensionData the {@code extension_data} bytes (0..65535 long)
     * @throws IllegalArgumentException on out-of-range type, oversize data, or null inputs
     */
    public MerkleTreeCertEntryExtension(int extensionType, byte[] extensionData)
    {
        if (extensionType < 0 || extensionType > 0xFFFF)
        {
            throw new IllegalArgumentException("extension_type out of uint16 range: " + extensionType);
        }
        if (extensionData == null)
        {
            throw new IllegalArgumentException("extension_data cannot be null");
        }
        if (extensionData.length > 0xFFFF)
        {
            throw new IllegalArgumentException("extension_data exceeds 2^16-1 bytes: " + extensionData.length);
        }
        this.extensionType = extensionType;
        this.extensionData = Arrays.clone(extensionData);
    }

    public int getExtensionType()
    {
        return extensionType;
    }

    public byte[] getExtensionData()
    {
        return Arrays.clone(extensionData);
    }
}
