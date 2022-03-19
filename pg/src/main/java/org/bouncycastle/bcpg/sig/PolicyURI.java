package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class PolicyURI
    extends SignatureSubpacket
{
    public PolicyURI(boolean critical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.POLICY_URL, critical, isLongLength, data);
    }

    public PolicyURI(boolean critical, String uri)
    {
        this(critical, false, Strings.toUTF8ByteArray(uri));
    }

    public String getURI()
    {
        return Strings.fromUTF8ByteArray(data);
    }

    public byte[] getRawURI()
    {
        return Arrays.clone(data);
    }
}
