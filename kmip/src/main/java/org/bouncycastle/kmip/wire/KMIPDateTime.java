package org.bouncycastle.kmip.wire;

import java.util.Date;

public class KMIPDateTime
    implements KMIPItem
{
    private final int tag;
    private final long value;

    public KMIPDateTime(int tag, Date value)
    {
        this.tag = tag;
        this.value = value.getTime();
    }

    public int getTag()
    {
        return tag;
    }

    public byte getType()
    {
        return KMIPType.DATE_TIME;
    }

    public long getLength()
    {
        return 8;
    }

    public Object getValue()
    {
        return new Date(value);
    }

    public KMIPItem toKMIPItem()
    {
        return this;
    }
}
