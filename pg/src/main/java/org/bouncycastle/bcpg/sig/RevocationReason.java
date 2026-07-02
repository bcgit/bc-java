package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
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
        super(SignatureSubpacketTags.REVOCATION_REASON, isCritical, isLongLength, verifyData(data));
    }

    public RevocationReason(boolean isCritical, byte reason, String description)
    {
        super(SignatureSubpacketTags.REVOCATION_REASON, isCritical, false, createData(reason, description));
    }

    private static byte[] createData(byte reason, String description)
    {
        return Arrays.prepend(Strings.toUTF8ByteArray(description), reason);
    }

    // RFC 9580 5.2.3.31: the Reason for Revocation body is 1 octet of revocation code
    // followed by an optional reason string, so at least one octet is required.
    private static byte[] verifyData(byte[] data)
    {
        if (data.length < 1)
        {
            throw new IllegalArgumentException("Truncated revocation reason subpacket");
        }
        return data;
    }

    public byte getRevocationReason()
    {
        return data[0];
    }

    public String getRevocationDescription()
    {
        if (data.length == 1)
        {
            return "";
        }

        return Strings.fromUTF8ByteArray(data, 1, data.length - 1);
    }
}
