package org.bouncycastle.kmip.wire;

import org.bouncycastle.util.Integers;

public class KMIPEnumeration
    implements KMIPItem
{
    private final int tag;
    private final Integer value;

    public KMIPEnumeration(int tag, int value)
    {
        this.tag = tag;
        this.value = Integers.valueOf(value);
    }

    public int getTag()
    {
        return tag;
    }

    public byte getType()
    {
        return KMIPType.ENUMERATION;
    }

    public long getLength()
    {
        return 4;
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
