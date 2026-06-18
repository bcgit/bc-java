package org.bouncycastle.asn1.cms;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <a href="https://tools.ietf.org/html/rfc6019">RFC 6019</a> {@code BinaryTime}
 * type — the unsigned integer count of seconds since 1970-01-01T00:00:00Z (UTC).
 * <pre>
 * BinaryTime ::= INTEGER (0..MAX)
 * </pre>
 * Used by other LAMPS specifications that need a compact, monotonically
 * increasing time value as part of an ASN.1 structure (e.g. RFC 9763
 * {@link RequesterCertificate#getRequestTime() RequesterCertificate.requestTime}).
 * The companion {@code id-aa-binarySigningTime} CMS signed attribute OID is
 * available as
 * {@link org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers#pkcs_9_at_binarySigningTime}.
 */
public class BinaryTime
    extends ASN1Object
{
    private final ASN1Integer time;

    public static BinaryTime getInstance(Object obj)
    {
        if (obj instanceof BinaryTime)
        {
            return (BinaryTime)obj;
        }
        if (obj != null)
        {
            return new BinaryTime(ASN1Integer.getInstance(obj));
        }
        return null;
    }

    /**
     * Construct a BinaryTime carrying the seconds-since-epoch of the supplied
     * {@link Date}. Sub-second components are discarded by truncation toward
     * negative infinity (consistent with {@link Date#getTime()} / 1000).
     *
     * @throws IllegalArgumentException if {@code date} is before the epoch
     *         (RFC 6019 prohibits negative values).
     */
    public BinaryTime(Date date)
    {
        long millis = date.getTime();
        long seconds = millis >= 0 ? millis / 1000 : (millis - 999) / 1000;
        if (seconds < 0)
        {
            throw new IllegalArgumentException("'date' cannot be before the epoch");
        }
        this.time = new ASN1Integer(seconds);
    }

    /**
     * Construct a BinaryTime carrying the supplied count of seconds since
     * 1970-01-01T00:00:00Z (UTC).
     *
     * @throws IllegalArgumentException if {@code seconds} is negative.
     */
    public BinaryTime(long seconds)
    {
        if (seconds < 0)
        {
            throw new IllegalArgumentException("'seconds' cannot be negative");
        }
        this.time = new ASN1Integer(seconds);
    }

    public BinaryTime(ASN1Integer time)
    {
        if (time == null)
        {
            throw new NullPointerException("'time' cannot be null");
        }
        if (time.isNegative())
        {
            throw new IllegalArgumentException("'time' cannot be negative");
        }
        this.time = time;
    }

    /**
     * @return the encoded value as a count of seconds since the Unix epoch.
     *         May exceed {@code Long.MAX_VALUE} on a wildly out-of-range
     *         encoding; callers that only need a Date may prefer
     *         {@link #toDate()} which rejects unrepresentable values.
     */
    public ASN1Integer getTime()
    {
        return time;
    }

    /**
     * Convert the encoded value to a {@link Date}.
     *
     * @throws ArithmeticException if the seconds value does not fit in a
     *         {@code long} after multiplication by 1000.
     */
    public Date toDate()
    {
        try
        {
            long seconds = time.longValueExact();
            if (seconds <= Long.MAX_VALUE / 1000L)
            {
                return new Date(seconds * 1000L);
            }
        }
        catch (ArithmeticException e)
        {
        }

        throw new ArithmeticException("BinaryTime out of Date range");
    }

    public ASN1Primitive toASN1Primitive()
    {
        return time;
    }
}
