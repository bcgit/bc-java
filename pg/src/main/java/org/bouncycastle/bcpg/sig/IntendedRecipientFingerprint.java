package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;

/**
 * packet giving the intended recipient fingerprint.
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
                    Arrays.concatenate(new byte[] { (byte)keyVersion }, fingerprint));
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
