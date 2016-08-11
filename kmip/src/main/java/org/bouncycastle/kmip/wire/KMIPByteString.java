package org.bouncycastle.kmip.wire;

import org.bouncycastle.util.Arrays;

public class KMIPByteString
    implements KMIPItem
{
    private final int tag;
    private final byte[] value;

    public KMIPByteString(int tag, byte[] value)
    {
        this.tag = tag;
        this.value = Arrays.clone(value);
    }

    public int getTag()
    {
        return tag;
    }

    public byte getType()
    {
        return KMIPType.BYTE_STRING;
    }

    public long getLength()
    {
        return value.length;
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
