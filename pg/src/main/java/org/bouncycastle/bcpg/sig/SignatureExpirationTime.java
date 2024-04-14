package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving signature expiration time.
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
