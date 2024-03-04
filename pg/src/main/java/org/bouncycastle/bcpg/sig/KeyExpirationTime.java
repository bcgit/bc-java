package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving time after creation at which the key expires.
 */
public class KeyExpirationTime 
    extends SignatureSubpacket
{
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
        long    time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        
        return time;
    }
}
