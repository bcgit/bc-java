package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.util.BigIntegers;


/**
 * Time64 ::= Uint64
 */
public class Time64
    extends UINT64
{
    /**
     * The ETSI Epoch for Time64
     */
    public static long etsiEpochMicros = Time32.etsiEpochMillis * 1000L;

    public Time64(long value)
    {
        this(BigInteger.valueOf(value));
    }

    public Time64(BigInteger value)
    {
        super(value);
    }

    public Time64(UINT64 uint64)
    {
        this(uint64.getValue());
    }

    /**
     * @return Time64 for now.
     */
    public static Time64 now()
    {
        return new Time64(1000 * System.currentTimeMillis() - etsiEpochMicros);
    }

    /**
     * Create from unix millis.
     *
     * @param unixMillis
     * @return
     */
    public static Time64 ofUnixMillis(long unixMillis)
    {
        // millis to micros - epoch in micro seconds.
        return new Time64((unixMillis * 1000L - etsiEpochMicros));
    }


    public static Time64 getInstance(Object o)
    {
        if (o instanceof UINT64)
        {
            return new Time64((UINT64)o);
        }

        if (o != null)
        {
            return new Time64(ASN1Integer.getInstance(o).getValue());
        }

        return null;
    }

    public long toUnixMillis()
    {
        // Value in uS + etsi epoch (uS) / 1000
        return (BigIntegers.longValueExact(getValue()) + etsiEpochMicros) / 1000L;
    }
}
