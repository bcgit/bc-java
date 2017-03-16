package org.bouncycastle.kmip.wire;

import java.math.BigInteger;

/**
 * The KMIP BigInteger.
 */
public class KMIPBigInteger
    implements KMIPItem<BigInteger>
{
    private final int tag;
    private final BigInteger value;

    public KMIPBigInteger(int tag, BigInteger value)
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
        return KMIPType.BIG_INTEGER;
    }

    public long getLength()
    {
        int length = value.toByteArray().length;

        if (length % 8 == 0)
        {
            return length;
        }

        return length + (8 - (length % 8));
    }

    public BigInteger getValue()
    {
        return value;
    }

    public KMIPItem toKMIPItem()
    {
        return this;
    }
}
