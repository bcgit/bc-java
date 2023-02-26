package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Regexp Packet - RFC 4880 5.2.3.14. Note: the RFC says the byte encoding is to be null terminated.
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
