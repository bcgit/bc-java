package org.bouncycastle.cert.plants;

import java.io.IOException;
import java.util.List;

/**
 * The name this class was published under before draft-ietf-plants-merkle-tree-certs-06
 * renamed the structure to {@code MTCLogEntry}.
 *
 * @deprecated use {@link MTCLogEntry}; the encoding is unchanged.
 */
@Deprecated
public class MerkleTreeCertEntry
    extends MTCLogEntry
{
    /**
     * @deprecated use {@link MTCLogEntry#MTCLogEntry(List, int, byte[])}
     */
    @Deprecated
    public MerkleTreeCertEntry(
        List<? extends MTCLogEntryExtension> extensions,
        int type,
        byte[] body)
    {
        super(extensions, type, body);
    }

    /**
     * @deprecated use {@link MTCLogEntry#MTCLogEntry(byte[])}
     */
    @Deprecated
    public MerkleTreeCertEntry(byte[] data)
        throws IOException
    {
        super(data);
    }
}
