package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Pack;

/**
 * packet giving the issuer key ID.
 */
public class IssuerKeyID 
    extends SignatureSubpacket
{
    protected static byte[] keyIDToBytes(
        long    keyId)
    {
        return Pack.longToBigEndian(keyId);
    }
    
    public IssuerKeyID(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.ISSUER_KEY_ID, critical, isLongLength, data);
    }
    
    public IssuerKeyID(
        boolean    critical,
        long       keyID)
    {
        super(SignatureSubpacketTags.ISSUER_KEY_ID, critical, false, keyIDToBytes(keyID));
    }
    
    public long getKeyID()
    {
        return Pack.bigEndianToLong(data, 0);
    }
}
