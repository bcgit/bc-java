package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;

/**
 * Signature Subpacket containing the fingerprint of the intended recipients primary key.
 * This packet can be used to prevent malicious forwarding/replay attacks.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-intended-recipient-fingerpr">
 *     RFC9580 - Intended Recipient Fingerprint</a>
 */
public class IntendedRecipientFingerprint
    extends SignatureSubpacket
{
    public IntendedRecipientFingerprint(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT, critical, isLongLength, verifyData(data));
    }

    public IntendedRecipientFingerprint(
        boolean    critical,
        int        keyVersion,
        byte[]     fingerprint)
    {
        super(SignatureSubpacketTags.INTENDED_RECIPIENT_FINGERPRINT, critical, false,
            Arrays.prepend(fingerprint, (byte)keyVersion));
    }

    private static byte[] verifyData(byte[] data)
    {
        if (data.length < 1)
        {
            throw new IllegalArgumentException("Data too short. Expect at least one octet of key version number.");
        }
        return data;
    }

    public int getKeyVersion()
    {
        return data[0] & 0xff;
    }

    public byte[] getFingerprint()
    {
        return Arrays.copyOfRange(data, 1, data.length);
    }

    public KeyIdentifier getKeyIdentifier()
    {
        return new KeyIdentifier(getFingerprint());
    }

}
