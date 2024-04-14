package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving time after creation at which the key expires.
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
