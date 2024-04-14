package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving whether or not is revocable.
 */
public class Revocable 
    extends SignatureSubpacket
{
    public Revocable(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.REVOCABLE, critical, isLongLength, data);
    }
    
    public Revocable(
        boolean    critical,
        boolean    isRevocable)
    {
        super(SignatureSubpacketTags.REVOCABLE, critical, false, Utils.booleanToByteArray(isRevocable));
    }
    
    public boolean isRevocable()
    {
        return Utils.booleanFromByteArray(data);
    }
}
