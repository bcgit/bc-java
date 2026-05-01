package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;

/**
 * Represents revocation key OpenPGP signature sub packet.
 * Note: This packet is deprecated. Applications MUST NOT generate such a packet.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.15">
 * RFC4880 - Revocation Key</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key">
 * RFC9580 - Revocation Key</a>
 * @deprecated since RFC9580
 */
public class RevocationKey
    extends SignatureSubpacket
{
    // 1 octet of class, 
    // 1 octet of public-key algorithm ID, 
    // 20 octets of fingerprint
    public RevocationKey(boolean isCritical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.REVOCATION_KEY, isCritical, isLongLength, data);
    }

    public RevocationKey(boolean isCritical, byte signatureClass, int keyAlgorithm, byte[] fingerprint)
    {
        super(SignatureSubpacketTags.REVOCATION_KEY, isCritical, false,
            createData(signatureClass, (byte)keyAlgorithm, fingerprint));
    }

    private static byte[] createData(byte signatureClass, byte keyAlgorithm, byte[] fingerprint)
    {
        byte[] data = new byte[2 + fingerprint.length];
        data[0] = signatureClass;
        data[1] = keyAlgorithm;
        System.arraycopy(fingerprint, 0, data, 2, fingerprint.length);
        return data;
    }

    public byte getSignatureClass()
    {
        return data[0];
    }

    public int getAlgorithm()
    {
        return data[1] & 0xff;
    }

    public byte[] getFingerprint()
    {
        return Arrays.copyOfRange(data, 2, data.length);
    }

    public KeyIdentifier getKeyIdentifier()
    {
        return new KeyIdentifier(getFingerprint());
    }
}
