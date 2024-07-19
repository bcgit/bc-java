package org.bouncycastle.bcpg;

/**
 * Basic PGP user attribute sub-packet tag types.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.12">
 *     RFC4880 - User Attribute Packet</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-user-attribute-packet-type-">
 *     C-R - User Attribute Packet</a>
 */
public interface UserAttributeSubpacketTags 
{
    /**
     * Tag for an {@link org.bouncycastle.bcpg.attr.ImageAttribute}.
     */
    int IMAGE_ATTRIBUTE = 1;
}
