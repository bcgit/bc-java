package org.bouncycastle.bcpg.sig;

/**
 * Revocation Key Class values.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.15">
 *     RFC4880 - Revocation Key</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key">
 *     RFC9580 - Revocation Key</a>
 */
public interface RevocationKeyTags
{
    byte CLASS_DEFAULT = (byte)0x80;

    /**
     * The revocation information is sensitive.
     */
    byte CLASS_SENSITIVE = (byte)0x40;

}
