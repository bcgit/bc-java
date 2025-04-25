package org.bouncycastle.bcpg.sig;

import java.util.Date;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket containing the time at which the signature was created.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.4">
 *     RFC4880 - Signature Creation Time</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-creation-time">
 *     RFC9580 - Signature Creation Time</a>
 */
public class SignatureCreationTime 
    extends SignatureSubpacket
{
    /**
     * @deprecated Will be removed
     */
    protected static byte[] timeToBytes(
        Date    date)
    {
        long t = date.getTime() / 1000;
        return Utils.timeToBytes(t);
    }

    public SignatureCreationTime(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.CREATION_TIME, critical, isLongLength, data);
    }

    public SignatureCreationTime(
        boolean    critical,
        Date       date)
    {
        super(SignatureSubpacketTags.CREATION_TIME, critical, false, timeToBytes(date));
    }

    public SignatureCreationTime(
            Date date)
    {
        this(true, date);
    }

    public Date getTime()
    {
        long time = Utils.timeFromBytes(data);
        return new Date(time * 1000);
    }
}
