package org.bouncycastle.bcpg.sig;

import java.util.Date;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving signature creation time.
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

    public Date getTime()
    {
        long time = Utils.timeFromBytes(data);
        return new Date(time * 1000);
    }
}
