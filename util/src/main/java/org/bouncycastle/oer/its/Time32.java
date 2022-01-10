package org.bouncycastle.oer.its;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

// Seconds since ETSI epoch which is 1 Jan 2004 00:00:00 UTC
public class Time32
    extends Uint32
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

    public Time32(Uint32 uint32)
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
        if (o instanceof Uint32)
        {
            return new Time32((Uint32)o);
        }
        else
        {
            return new Time32(ASN1Integer.getInstance(o).getValue());
        }
    }

    public long toUnixMillis()
    {
        return (getValue() * 1000L) + etsiEpochMillis;
    }

}
