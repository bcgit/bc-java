package org.bouncycastle.kmip.wire;

import org.bouncycastle.util.Strings;

public class KMIPTextString
    implements KMIPItem
{
    private final int tag;
    private final String value;

    public KMIPTextString(int tag, String value)
    {
        this.tag = tag;
        this.value = value;
    }

    public int getTag()
    {
        return tag;
    }

    public byte getType()
    {
        return KMIPType.TEXT_STRING;
    }

    public long getLength()
    {
        return Strings.toUTF8ByteArray(value).length;
    }

    public Object getValue()
    {
        return value;
    }

    public KMIPItem toKMIPItem()
    {
        return this;
    }
}
