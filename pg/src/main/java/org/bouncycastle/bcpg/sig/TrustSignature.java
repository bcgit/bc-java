package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket encoding the level and amount of trust the issuer places into the certified key or identity.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.10">
 *     RFC4880 - Trust Packet</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-trust-signature">
 *     RFC9580 - Trust Signature</a>
 */
public class TrustSignature 
    extends SignatureSubpacket
{    
    private static byte[] intToByteArray(
        int    v1,
        int    v2)
    {
        byte[]    data = new byte[2];
        
        data[0] = (byte)v1;
        data[1] = (byte)v2;
        
        return data;
    }
    
    public TrustSignature(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.TRUST_SIG, critical, isLongLength, data);
    }
    
    public TrustSignature(
        boolean    critical,
        int        depth,
        int        trustAmount)
    {
        super(SignatureSubpacketTags.TRUST_SIG, critical, false, intToByteArray(depth, trustAmount));
    }
    
    public int getDepth()
    {
        return data[0] & 0xff;
    }
    
    public int getTrustAmount()
    {
        return data[1] & 0xff;
    }
}
