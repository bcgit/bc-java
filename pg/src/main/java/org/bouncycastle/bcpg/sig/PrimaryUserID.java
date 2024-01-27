package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Booleans;

/**
 * Signature Subpacket indicating, whether the signed User-ID is marked as the primary user ID for the key.
 */
public class PrimaryUserID 
    extends SignatureSubpacket
{
    public PrimaryUserID(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.PRIMARY_USER_ID, critical, isLongLength, data);
    }
    
    public PrimaryUserID(
        boolean    critical,
        boolean    isPrimaryUserID)
    {
        super(SignatureSubpacketTags.PRIMARY_USER_ID, critical, false, Booleans.toByteArray(isPrimaryUserID));
    }
    
    public boolean isPrimaryUserID()
    {
        return Booleans.fromByteArray(data);
    }
}
