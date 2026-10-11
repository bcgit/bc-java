package org.bouncycastle.cert.plants;

/**
 * The name this class was published under before draft-ietf-plants-merkle-tree-certs-06
 * renamed the structure to {@code MTCLogEntryExtension}.
 *
 * @deprecated use {@link MTCLogEntryExtension}; the encoding is unchanged.
 */
@Deprecated
public class MerkleTreeCertEntryExtension
    extends MTCLogEntryExtension
{
    /**
     * @deprecated use {@link MTCLogEntryExtension#MTCLogEntryExtension(int, byte[])}
     */
    @Deprecated
    public MerkleTreeCertEntryExtension(int extensionType, byte[] extensionData)
    {
        super(extensionType, extensionData);
    }
}
