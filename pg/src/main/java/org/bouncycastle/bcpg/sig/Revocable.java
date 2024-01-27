package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Booleans;

/**
 * Signature subpacket indicating, whether the carrying signature can be revoked.
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
        super(SignatureSubpacketTags.REVOCABLE, critical, false, Booleans.toByteArray(isRevocable));
    }
    
    public boolean isRevocable()
    {
        return Booleans.fromByteArray(data);
    }
}
