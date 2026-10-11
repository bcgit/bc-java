package org.bouncycastle.cert.plants;

/**
 * The name this class was published under before draft-ietf-plants-merkle-tree-certs-06
 * renamed the structure to {@code CosignedSubtree}. The static {@code encode}
 * methods are inherited from {@link MTCCosignedSubtree}.
 *
 * @deprecated use {@link MTCCosignedSubtree}; the encoding is unchanged.
 */
@Deprecated
public class MTCCosignedMessage
    extends MTCCosignedSubtree
{
    private MTCCosignedMessage()
    {
    }
}
