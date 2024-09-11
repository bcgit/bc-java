package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket containing the number of seconds after the key's creation date, after which the key expires.
 * The special value of {@code 0} means that the key never expires.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.6">
 *     RFC4880 - Key Expiration Time</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-key-expiration-time">
 *     RFC9580 - Key Expiration Time</a>
 */
public class KeyExpirationTime 
    extends SignatureSubpacket
{
    /**
     * @deprecated Will be removed
     */
    protected static byte[] timeToBytes(
        long    t)
    {
        return Utils.timeToBytes(t);
    }

    public KeyExpirationTime(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.KEY_EXPIRE_TIME, critical, isLongLength, data);
    }

    public KeyExpirationTime(
        boolean    critical,
        long       seconds)
    {
        super(SignatureSubpacketTags.KEY_EXPIRE_TIME, critical, false, Utils.timeToBytes(seconds));
    }

    /**
     * Return the number of seconds after creation time a key is valid for.
     * 
     * @return second count for key validity.
     */
    public long getTime()
    {
        return Utils.timeFromBytes(data);
    }
}
