package org.bouncycastle.bcpg;

/**
 * Basic PGP user attribute sub-packet tag types.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.12">
 *     RFC4880 - User Attribute Packet</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-user-attribute-packet-type-">
 *     RFC9580 - User Attribute Packet</a>
 */
public interface UserAttributeSubpacketTags 
{
    /**
     * Tag for an {@link org.bouncycastle.bcpg.attr.ImageAttribute}.
     */
    int IMAGE_ATTRIBUTE = 1;
}
