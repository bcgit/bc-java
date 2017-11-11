package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

/**
 * Base class representing the ASN.1 GeneralizedTime type.
 * <p>
 * The main difference between these and UTC time is a 4 digit year.
 * </p>
 */
public class ASN1GeneralizedTime
    extends ASN1Primitive
{
    private final Bytes time;

    /**
     * return a generalized time from the passed in object
     *
     * @param obj an ASN1GeneralizedTime or an object that can be converted into one.
     * @return an ASN1GeneralizedTime instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1GeneralizedTime getInstance(
        final Object obj)
    {
        if (obj == null || obj instanceof ASN1GeneralizedTime)
        {
            return (ASN1GeneralizedTime)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (ASN1GeneralizedTime)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Generalized Time object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @return an ASN1GeneralizedTime instance.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     */
    public static ASN1GeneralizedTime getInstance(
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1GeneralizedTime)
        {
            return getInstance(o);
        }
        else
        {
            return new ASN1GeneralizedTime(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * The correct format for this is YYYYMMDDHHMMSS[.f]Z, or without the Z
     * for local time, or Z+-HHMM on the end, for difference between local
     * time and UTC time. The fractional second amount f must consist of at
     * least one number with trailing zeroes removed.
     *
     * @param time the time string.
     * @throws IllegalArgumentException if String is an illegal format.
     */
    public ASN1GeneralizedTime(
        final String time)
    {
        this.time = Strings.toByteArray(time);
        try
        {
            getDate();
        }
        catch (final ParseException e)
        {
            throw new IllegalArgumentException("invalid date string: " + e.getMessage());
        }
    }

    /**
     * Base constructor from a java.util.date object
     *
     * @param time a date object representing the time of interest.
     */
    public ASN1GeneralizedTime(
        final Date time)
    {
        final SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

        this.time = Strings.toByteArray(dateF.format(time));
    }

    /**
     * Base constructor from a java.util.date and Locale - you may need to use this if the default locale
     * doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
     *
     * @param time a date object representing the time of interest.
     * @param locale an appropriate Locale for producing an ASN.1 GeneralizedTime value.
     */
    public ASN1GeneralizedTime(
        final Date time,
        final Locale locale)
    {
        final SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'", locale);

        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

        this.time = Strings.toByteArray(dateF.format(time));
    }

    ASN1GeneralizedTime(
        final Bytes bytes)
    {
        time = bytes;
    }

    /**
     * Return the time.
     *
     * @return The time string as it appeared in the encoded object.
     */
    public String getTimeString()
    {
        return Strings.fromByteArray(time);
    }

    /**
     * return the time - always in the form of
     * YYYYMMDDhhmmssGMT(+hh:mm|-hh:mm).
     * <p>
     * Normally in a certificate we would expect "Z" rather than "GMT",
     * however adding the "GMT" means we can just use:
     * <pre>
     *     dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
     * </pre>
     * To read in the time and get a date which is compatible with our local
     * time zone.
     * </p>
     * @return a String representation of the time.
     */
    public String getTime()
    {
        final String stime = Strings.fromByteArray(time);

        //
        // standardise the format.
        //
        if (stime.charAt(stime.length() - 1) == 'Z')
        {
            return stime.substring(0, stime.length() - 1) + "GMT+00:00";
        }
        else
        {
            int signPos = stime.length() - 5;
            char sign = stime.charAt(signPos);
            if (sign == '-' || sign == '+')
            {
                return stime.substring(0, signPos)
                    + "GMT"
                    + stime.substring(signPos, signPos + 3)
                    + ":"
                    + stime.substring(signPos + 3);
            }
            else
            {
                signPos = stime.length() - 3;
                sign = stime.charAt(signPos);
                if (sign == '-' || sign == '+')
                {
                    return stime.substring(0, signPos)
                        + "GMT"
                        + stime.substring(signPos)
                        + ":00";
                }
            }
        }
        return stime + calculateGMTOffset();
    }

    private String calculateGMTOffset()
    {
        String sign = "+";
        final TimeZone timeZone = TimeZone.getDefault();
        int offset = timeZone.getRawOffset();
        if (offset < 0)
        {
            sign = "-";
            offset = -offset;
        }
        int hours = offset / (60 * 60 * 1000);
        final int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

        try
        {
            if (timeZone.useDaylightTime() && timeZone.inDaylightTime(getDate()))
            {
                hours += sign.equals("+") ? 1 : -1;
            }
        }
        catch (final ParseException e)
        {
            // we'll do our best and ignore daylight savings
        }

        return "GMT" + sign + convert(hours) + ":" + convert(minutes);
    }

    private String convert(final int time)
    {
        if (time < 10)
        {
            return "0" + time;
        }

        return Integer.toString(time);
    }

    public Date getDate()
        throws ParseException
    {
        SimpleDateFormat dateF;
        final String stime = Strings.fromByteArray(time);
        String d = stime;

        if (stime.endsWith("Z"))
        {
            if (hasFractionalSeconds())
            {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
            }
            else
            {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            }

            dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        }
        else if (stime.indexOf('-') > 0 || stime.indexOf('+') > 0)
        {
            d = getTime();
            if (hasFractionalSeconds())
            {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
            }
            else
            {
                dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
            }

            dateF.setTimeZone(new SimpleTimeZone(0, "Z"));
        }
        else
        {
            if (hasFractionalSeconds())
            {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
            }
            else
            {
                dateF = new SimpleDateFormat("yyyyMMddHHmmss");
            }

            dateF.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
        }

        if (hasFractionalSeconds())
        {
            // java misinterprets extra digits as being milliseconds...
            String frac = d.substring(14);
            int index;
            for (index = 1; index < frac.length(); index++)
            {
                final char ch = frac.charAt(index);
                if (!('0' <= ch && ch <= '9'))
                {
                    break;
                }
            }

            if (index - 1 > 3)
            {
                frac = frac.substring(0, 4) + frac.substring(index);
                d = d.substring(0, 14) + frac;
            }
            else if (index - 1 == 1)
            {
                frac = frac.substring(0, index) + "00" + frac.substring(index);
                d = d.substring(0, 14) + frac;
            }
            else if (index - 1 == 2)
            {
                frac = frac.substring(0, index) + "0" + frac.substring(index);
                d = d.substring(0, 14) + frac;
            }
        }

        return dateF.parse(d);
    }

    private boolean hasFractionalSeconds()
    {
        for (int i = 0; i != time.size(); i++)
        {
            if (time.getByte(i) == '.')
            {
                if (i == 14)
                {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        final int length = time.size();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.GENERALIZED_TIME, time);
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1GeneralizedTime))
        {
            return false;
        }

        return time.equals(((ASN1GeneralizedTime)o).time);
    }

    @Override
    public int hashCode()
    {
        return time.hashCode();
    }
}
