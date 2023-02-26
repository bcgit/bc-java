package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;

/**
 * packet giving the issuer key fingerprint.
 */
public class IssuerFingerprint
    extends SignatureSubpacket
{
    public IssuerFingerprint(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.ISSUER_FINGERPRINT, critical, isLongLength, data);
    }

    public IssuerFingerprint(
        boolean    critical,
        int        keyVersion,
        byte[]     fingerprint)
    {
        super(SignatureSubpacketTags.ISSUER_FINGERPRINT, critical, false,
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
