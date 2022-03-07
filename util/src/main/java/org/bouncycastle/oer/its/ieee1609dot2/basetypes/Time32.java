package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;

// Seconds since ETSI epoch which is 1 Jan 2004 00:00:00 UTC
public class Time32
    extends UINT32
{
    /**
     * The ETSI Epoch for Time32
     */
    public static long etsiEpochMillis = 1072915200000L;

    public Time32(long value)
    {
        super(value);
    }

    public Time32(BigInteger value)
    {
        super(value);
    }

    public Time32(UINT32 uint32)
    {
        this(uint32.getValue());
    }

    /**
     * @return Time32 for now.
     */
    public static Time32 now()
    {
        return ofUnixMillis(System.currentTimeMillis());
    }

    /**
     * Create from unix millis.
     *
     * @param unixMillis
     * @return
     */
    public static Time32 ofUnixMillis(long unixMillis)
    {
        return new Time32((unixMillis - etsiEpochMillis) / 1000);
    }

    public static Time32 getInstance(Object o)
    {
        if (o instanceof UINT32)
        {
            return new Time32((UINT32)o);
        }
        if (o != null)
        {
            return new Time32(ASN1Integer.getInstance(o).getValue());
        }
        return null;
    }

    public long toUnixMillis()
    {
        return (getValue().longValue() * 1000L) + etsiEpochMillis;
    }

    @Override
    public String toString()
    {
        return new Date(toUnixMillis()).toString();
    }
}
