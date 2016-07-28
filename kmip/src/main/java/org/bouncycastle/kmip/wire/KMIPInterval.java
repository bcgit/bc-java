package org.bouncycastle.kmip.wire;

public class KMIPInterval
    implements KMIPItem
{
    private final int tag;
    private final long value;

    public KMIPInterval(int tag, long value)
    {
        if (value > 0xffffffffL || value < 0)
        {
            throw new IllegalArgumentException("interval value out of range");
        }

        this.tag = tag;
        this.value = value;
    }

    public int getTag()
    {
        return tag;
    }

    public byte getType()
    {
        return KMIPType.INTERVAL;
    }

    public long getLength()
    {
        return 4;
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
