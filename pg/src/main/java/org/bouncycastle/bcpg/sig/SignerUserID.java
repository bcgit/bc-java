package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Signature Subpacket containing the User ID of the identity as which the issuer created the signature.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.22">
 *     RFC4880 - Signer's User ID</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signers-user-id">
 *     RFC9580 - Signer's User ID</a>
 */
public class SignerUserID 
    extends SignatureSubpacket
{
    public SignerUserID(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, isLongLength, data);
    }
    
    public SignerUserID(
        boolean    critical,
        String     userID)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, false, Strings.toUTF8ByteArray(userID));
    }
    
    public String getID()
    {
        return Strings.fromUTF8ByteArray(data);
    }

    public byte[] getRawID()
    {
        return Arrays.clone(data);
    }
}
