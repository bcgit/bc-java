package org.bouncycastle.cert.plants;

/**
 * The name this class was published under before draft-ietf-plants-merkle-tree-certs-06
 * renamed the structure to {@code Cosignature}.
 *
 * @deprecated use {@link MTCCosignature}; the encoding is unchanged.
 */
@Deprecated
public class MTCSignature
    extends MTCCosignature
{
    /**
     * @deprecated use {@link MTCCosignature#MTCCosignature(byte[], byte[])}
     */
    @Deprecated
    public MTCSignature(byte[] cosignerId, byte[] signature)
    {
        super(cosignerId, signature);
    }
}
