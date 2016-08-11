package org.bouncycastle.kmip.wire;

public class KMIPBoolean
    implements KMIPItem
{
    private final int tag;
    private final boolean value;

    public KMIPBoolean(int tag, boolean value)
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
        return KMIPType.BOOLEAN;
    }

    public long getLength()
    {
        return 8;
    }

    public Object getValue()
    {
        return value ? Boolean.TRUE : Boolean.FALSE;
    }

    public KMIPItem toKMIPItem()
    {
        return this;
    }
}
