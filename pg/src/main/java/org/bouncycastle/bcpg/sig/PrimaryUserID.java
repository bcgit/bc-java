package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket marking a User ID as primary.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.19">
 *     RFC4880 - Primary User ID</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-primary-user-id">
 *     RFC9580 - Primary User ID</a>
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
        super(SignatureSubpacketTags.PRIMARY_USER_ID, critical, false, Utils.booleanToByteArray(isPrimaryUserID));
    }
    
    public boolean isPrimaryUserID()
    {
        return Utils.booleanFromByteArray(data);
    }
}
