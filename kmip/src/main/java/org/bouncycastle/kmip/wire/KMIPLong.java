package org.bouncycastle.kmip.wire;

public class KMIPLong
    implements KMIPItem
{
    private final int tag;
    private final long value;

    public KMIPLong(int tag, long value)
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
        return KMIPType.LONG_INTEGER;
    }

    public long getLength()
    {
        return 8;
    }

    public Object getValue()
    {
        return new Long(value);
    }

    public KMIPItem toKMIPItem()
    {
        return this;
    }
}
