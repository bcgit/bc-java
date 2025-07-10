package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;

/**
 * Signature Subpacket containing the fingerprint of the issuers signing (sub-) key.
 * This packet supersedes the {@link IssuerKeyID} subpacket.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-fingerprint">
 *     RFC9580 - Issuer Fingerprint</a>
 */
public class IssuerFingerprint
    extends SignatureSubpacket
{
    public IssuerFingerprint(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.ISSUER_FINGERPRINT, critical, isLongLength, verifyData(data));
    }

    public IssuerFingerprint(
        boolean    critical,
        int        keyVersion,
        byte[]     fingerprint)
    {
        super(SignatureSubpacketTags.ISSUER_FINGERPRINT, critical, false,
            Arrays.prepend(fingerprint, (byte)keyVersion));
    }

    private static byte[] verifyData(byte[] data)
    {
        if (data.length < 1)
        {
            throw new IllegalArgumentException("Data too short. Expect at least one octet of key version.");
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

    public long getKeyID()
    {
        if (getKeyVersion() == PublicKeyPacket.VERSION_4)
        {
            return FingerprintUtil.keyIdFromV4Fingerprint(getFingerprint());
        }
        if (getKeyVersion() == PublicKeyPacket.LIBREPGP_5)
        {
            return FingerprintUtil.keyIdFromLibrePgpFingerprint(getFingerprint());
        }
        if (getKeyVersion() == PublicKeyPacket.VERSION_6)
        {
            return FingerprintUtil.keyIdFromV6Fingerprint(getFingerprint());
        }
        return 0;
    }

    public KeyIdentifier getKeyIdentifier()
    {
        return new KeyIdentifier(getFingerprint());
    }
}
