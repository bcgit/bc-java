package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket containing the number of seconds after the signatures creation
 * time after which the signature expires.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.10">
 *     RFC4880 - Signature Expiration Time</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-expiration-time">
 *     RFC9580 - Signature Expiration Time</a>
 */
public class SignatureExpirationTime 
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

    public SignatureExpirationTime(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.EXPIRE_TIME, critical, isLongLength, data);
    }

    public SignatureExpirationTime(
        boolean    critical,
        long       seconds)
    {
        super(SignatureSubpacketTags.EXPIRE_TIME, critical, false, Utils.timeToBytes(seconds));
    }

    /**
     * return time in seconds before signature expires after creation time.
     */
    public long getTime()
    {
        return Utils.timeFromBytes(data);
    }
}
