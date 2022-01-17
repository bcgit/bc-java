package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class RegularExpression
        extends SignatureSubpacket
{

    public RegularExpression(
            boolean critical,
            boolean isLongLength,
            byte[] data)
    {
        super(SignatureSubpacketTags.REG_EXP, critical, isLongLength, data);
    }

    public RegularExpression(
            boolean critical,
            String regex)
    {
        super(SignatureSubpacketTags.REG_EXP, critical, false, Strings.toUTF8ByteArray(regex));
    }

    public String getRegex()
    {
        return Strings.fromUTF8ByteArray(data);
    }

    public byte[] getRawRegex()
    {
        return Arrays.clone(data);
    }
}
