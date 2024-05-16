package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * packet giving the issuer key ID.
 */
public class IssuerKeyID 
    extends SignatureSubpacket
{
    protected static byte[] keyIDToBytes(
        long    keyId)
    {
        byte[]    data = new byte[8];
        FingerprintUtil.writeKeyID(keyId, data);
        return data;
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
        return FingerprintUtil.readKeyID(data);
    }
}
