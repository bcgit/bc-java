package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;

/**
 * Signature Subpacket containing the hash value of another signature to which this signature applies to.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.25">
 *     RFC4880 - Signature Target</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-target">
 *     RFC9580 - Signature Target</a>
 */
public class SignatureTarget
    extends SignatureSubpacket
{
    public SignatureTarget(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.SIGNATURE_TARGET, critical, isLongLength, verifyData(data));
    }

    public SignatureTarget(
        boolean    critical,
        int        publicKeyAlgorithm,
        int        hashAlgorithm,
        byte[]     hashData)
    {
        super(SignatureSubpacketTags.SIGNATURE_TARGET, critical, false, Arrays.concatenate(new byte[] { (byte)publicKeyAlgorithm, (byte)hashAlgorithm }, hashData));
    }

    // RFC 9580 5.2.3.33: the Signature Target body is 1 octet public-key algorithm, 1 octet
    // hash algorithm, then N octets of hash; the two leading octets must be present.
    private static byte[] verifyData(byte[] data)
    {
        if (data.length < 2)
        {
            throw new IllegalArgumentException("Truncated signature target subpacket");
        }
        return data;
    }

    public int getPublicKeyAlgorithm()
    {
        return data[0] & 0xff;
    }

    public int getHashAlgorithm()
    {
        return data[1] & 0xff;
    }

    public byte[] getHashData()
    {
        return Arrays.copyOfRange(data, 2, data.length);
    }
}
