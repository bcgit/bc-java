package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket marking a signature as non-revocable.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.12">
 *     RFC4880 - Revocable</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-revocable">
 *     C-R - Revocable</a>
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
