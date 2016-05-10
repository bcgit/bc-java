package com.github.gv2011.bcasn.asn1.cms;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;

import com.github.gv2011.bcasn.asn1.ASN1Choice;
import com.github.gv2011.bcasn.asn1.ASN1GeneralizedTime;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.ASN1UTCTime;
import com.github.gv2011.bcasn.asn1.DERGeneralizedTime;
import com.github.gv2011.bcasn.asn1.DERUTCTime;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-11.3">RFC 5652</a>:
 * Dual-mode timestamp format producing either UTCTIme or GeneralizedTime.
 * <p>
 * <pre>
 * Time ::= CHOICE {
 *     utcTime        UTCTime,
 *     generalTime    GeneralizedTime }
 * </pre>
 * <p>
 * This has a constructor using java.util.Date for input which generates
 * a {@link com.github.gv2011.bcasn.asn1.DERUTCTime DERUTCTime} object if the
 * supplied datetime is in range 1950-01-01-00:00:00 UTC until 2049-12-31-23:59:60 UTC.
 * If the datetime value is outside that range, the generated object will be
 * {@link com.github.gv2011.bcasn.asn1.DERGeneralizedTime DERGeneralizedTime}.
 */
public class Time
    extends ASN1Object
    implements ASN1Choice
{
    ASN1Primitive time;

    public static Time getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject());
    }

    /**
     * @deprecated use getInstance()
     */
    public Time(
        ASN1Primitive   time)
    {
        if (!(time instanceof ASN1UTCTime)
            && !(time instanceof ASN1GeneralizedTime))
        {
            throw new IllegalArgumentException("unknown object passed to Time");
        }

        this.time = time; 
    }

    /**
     * Creates a time object from a given date - if the date is between 1950
     * and 2049 a UTCTime object is generated, otherwise a GeneralizedTime
     * is used.
     *
     * @param time a date object representing the time of interest.
     */
    public Time(
        Date    time)
    {
        SimpleTimeZone      tz = new SimpleTimeZone(0, "Z");
        SimpleDateFormat    dateF = new SimpleDateFormat("yyyyMMddHHmmss");

        dateF.setTimeZone(tz);

        String  d = dateF.format(time) + "Z";
        int     year = Integer.parseInt(d.substring(0, 4));

        if (year < 1950 || year > 2049)
        {
            this.time = new DERGeneralizedTime(d);
        }
        else
        {
            this.time = new DERUTCTime(d.substring(2));
        }
    }

    /**
     * Creates a time object from a given date and locale - if the date is between 1950
     * and 2049 a UTCTime object is generated, otherwise a GeneralizedTime
     * is used. You may need to use this constructor if the default locale
     * doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
     *
     * @param time a date object representing the time of interest.
     * @param locale an appropriate Locale for producing an ASN.1 GeneralizedTime value.
     */
    public Time(
        Date    time,
        Locale locale)
    {
        SimpleTimeZone      tz = new SimpleTimeZone(0, "Z");
        SimpleDateFormat    dateF = new SimpleDateFormat("yyyyMMddHHmmss", locale);

        dateF.setTimeZone(tz);

        String  d = dateF.format(time) + "Z";
        int     year = Integer.parseInt(d.substring(0, 4));

        if (year < 1950 || year > 2049)
        {
            this.time = new DERGeneralizedTime(d);
        }
        else
        {
            this.time = new DERUTCTime(d.substring(2));
        }
    }

    /**
     * Return a Time object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link Time} object
     * <li> {@link com.github.gv2011.bcasn.asn1.DERUTCTime DERUTCTime} object
     * <li> {@link com.github.gv2011.bcasn.asn1.DERGeneralizedTime DERGeneralizedTime} object
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Time getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof Time)
        {
            return (Time)obj;
        }
        else if (obj instanceof ASN1UTCTime)
        {
            return new Time((ASN1UTCTime)obj);
        }
        else if (obj instanceof ASN1GeneralizedTime)
        {
            return new Time((ASN1GeneralizedTime)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    /**
     * Get the date+tine as a String in full form century format.
     */
    public String getTime()
    {
        if (time instanceof ASN1UTCTime)
        {
            return ((ASN1UTCTime)time).getAdjustedTime();
        }
        else
        {
            return ((ASN1GeneralizedTime)time).getTime();
        }
    }

    /**
     * Get java.util.Date version of date+time.
     */
    public Date getDate()
    {
        try
        {
            if (time instanceof ASN1UTCTime)
            {
                return ((ASN1UTCTime)time).getAdjustedDate();
            }
            else
            {
                return ((ASN1GeneralizedTime)time).getDate();
            }
        }
        catch (ParseException e)
        {         // this should never happen
            throw new IllegalStateException("invalid date string: " + e.getMessage());
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return time;
    }
}
