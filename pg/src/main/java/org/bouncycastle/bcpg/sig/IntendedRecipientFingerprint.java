package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;

/**
 * Signature Subpacket containing the fingerprint of the intended recipients primary key.
 * This packet can be used to prevent malicious forwarding/replay attacks.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-intended-recipient-fingerpr">
 *     C-R - Intended Recipient Fingerprint</a>
 */
public class IntendedRecipientFingerprint
    extends SignatureSubpacket
{
    public IntendedRecipientFingerprint(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT, critical, isLongLength, data);
    }

    public IntendedRecipientFingerprint(
        boolean    critical,
        int        keyVersion,
        byte[]     fingerprint)
    {
        super(SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT, critical, false,
            Arrays.prepend(fingerprint, (byte)keyVersion));
    }

    public int getKeyVersion()
    {
        return data[0] & 0xff;
    }

    public byte[] getFingerprint()
    {
        return Arrays.copyOfRange(data, 1, data.length);
    }
}
