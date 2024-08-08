package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Signature Subpacket containing a regular expression limiting the scope of the signature.
 * Note: the RFC says the byte encoding is to be null terminated.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.14">
 *     RFC4880 - Regular Expression</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-regular-expression">
 *     RFC9580 - Regular Expression</a>
 */
public class RegularExpression
    extends SignatureSubpacket
{
    public RegularExpression(
            boolean critical,
            boolean isLongLength,
            byte[] data)
    {
        super(SignatureSubpacketTags.REG_EXP, critical, isLongLength, data);
        if (data[data.length - 1] != 0)
        {
            throw new IllegalArgumentException("data in regex missing null termination");
        }
    }

    public RegularExpression(
            boolean critical,
            String regex)
    {
        super(
                SignatureSubpacketTags.REG_EXP,
                critical,
                false,
                toNullTerminatedUTF8ByteArray(regex));
    }

    public String getRegex()
    {
        // last byte is null terminator
        return Strings.fromUTF8ByteArray(data, 0, data.length - 1);
    }

    public byte[] getRawRegex()
    {
        return Arrays.clone(data);
    }

    private static byte[] toNullTerminatedUTF8ByteArray(String string)
    {
        byte[] utf8 = Strings.toUTF8ByteArray(string);
        return Arrays.append(utf8, (byte)0);
    }
}
