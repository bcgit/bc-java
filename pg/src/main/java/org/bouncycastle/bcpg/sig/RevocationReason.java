package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Strings;

/**
 * Signature Subpacket for encoding the reason why a key was revoked.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.23">
 *     RFC4880 - Reason for Revocation</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-reason-for-revocation">
 *     RFC9580 - Reason for Revocation</a>
 */
public class RevocationReason extends SignatureSubpacket
{
    public RevocationReason(boolean isCritical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.REVOCATION_REASON, isCritical, isLongLength, data);
    }

    public RevocationReason(boolean isCritical, byte reason, String description)
    {
        super(SignatureSubpacketTags.REVOCATION_REASON, isCritical, false, createData(reason, description));
    }

    private static byte[] createData(byte reason, String description)
    {
        byte[] descriptionBytes = Strings.toUTF8ByteArray(description);
        byte[] data = new byte[1 + descriptionBytes.length];

        data[0] = reason;
        System.arraycopy(descriptionBytes, 0, data, 1, descriptionBytes.length);

        return data;
    }

    public byte getRevocationReason()
    {
        return getData()[0];
    }

    public String getRevocationDescription()
    {
        byte[] data = getData();
        if (data.length == 1)
        {
            return "";
        }

        byte[] description = new byte[data.length - 1];
        System.arraycopy(data, 1, description, 0, description.length);

        return Strings.fromUTF8ByteArray(description);
    }
}
