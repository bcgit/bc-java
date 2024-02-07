package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving signature expiration time.
 */
public class SignatureExpirationTime 
    extends SignatureSubpacket
{
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
        long    time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        
        return time;
    }
}
