package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * packet giving the User ID of the signer.
 */
public class SignerUserID 
    extends SignatureSubpacket
{
    public SignerUserID(
        boolean    critical,
        byte[]     data)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, data);
    }
    
    public SignerUserID(
        boolean    critical,
        String     userID)
    {
        super(SignatureSubpacketTags.SIGNER_USER_ID, critical, Strings.toUTF8ByteArray(userID));
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
