package org.bouncycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
- * UTC time object.
 * Internal facade of {@link ASN1UTCTime}.
 * <p>
 * This datatype is valid only from 1950-01-01 00:00:00 UTC until 2049-12-31 23:59:59 UTC.
 * </p>
 * <hr>
 * <p><b>X.690</b></p>
 * <p><b>11: Restrictions on BER employed by both CER and DER</b></p>
 * <p><b>11.8 UTCTime </b></p>
 * <b>11.8.1</b> The encoding shall terminate with "Z",
 * as described in the ITU-T X.680 | ISO/IEC 8824-1 clause on UTCTime.
 * <p>
 * <b>11.8.2</b> The seconds element shall always be present.
 * <p>
 * <b>11.8.3</b> Midnight (GMT) shall be represented in the form:
 * <blockquote>
 * "YYMMDD000000Z"
 * </blockquote>
 * where "YYMMDD" represents the day following the midnight in question.
 */
public class ASN1UTCTime
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UTCTime.class, BERTags.UTC_TIME)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return an UTC Time from the passed in object.
     *
     * @param obj an ASN1UTCTime or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1UTCTime instance, or null.
     */
    public static ASN1UTCTime getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1UTCTime)
        {
            return (ASN1UTCTime)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1UTCTime)
            {
                return (ASN1UTCTime)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1UTCTime)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an UTC Time from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want
     * @param declaredExplicit true if the object is meant to be explicitly tagged false
     *                     otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1UTCTime instance, or null.
     */
    public static ASN1UTCTime getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return (ASN1UTCTime)TYPE.getContextTagged(taggedObject, declaredExplicit);
    }

    public static ASN1UTCTime getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return (ASN1UTCTime)TYPE.getTagged(taggedObject, declaredExplicit);
    }

    final byte[] contents;

    /**
     * The correct format for this is YYMMDDHHMMSSZ (it used to be that seconds were
     * never encoded. When you're creating one of these objects from scratch, that's
     * what you want to use, otherwise we'll try to deal with whatever gets read from
     * the input stream... (this is why the input format is different from the getTime()
     * method output).
     * <p>
     *
     * @param time the time string.
     */
    public ASN1UTCTime(
        String time)
    {
        this.contents = Strings.toByteArray(time);
        try
        {
            this.getDate();
        }
        catch (ParseException e)
        {
            throw Exceptions.illegalArgumentException("invalid date string", e);
        }
    }

    /**
     * Base constructor from a java.util.date object
     * @param time the Date to build the time from.
     */
    public ASN1UTCTime(
        Date time)
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'", LocaleUtil.EN_Locale);

        dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

        this.contents = Strings.toByteArray(dateF.format(time));
    }

    /**
     * Base constructor from a {@link Date} and an explicit {@link Locale}. The {@code locale}
     * selects the calendar used by the underlying {@link SimpleDateFormat}. Most callers
     * should prefer the simple {@link #ASN1UTCTime(Date)} form, which always formats under an
     * English Gregorian locale (so the encoded year is the spec-mandated Gregorian one
     * regardless of {@link Locale#getDefault()}, including on JVMs whose default uses a
     * non-Gregorian calendar such as Thai Buddhist {@code th_TH_TH_#u-nu-thai} or Japanese
     * Imperial {@code ja_JP_JP_#u-ca-japanese}). Reach for this {@code (Date, Locale)} form
     * only when you need explicit control over the formatter's calendar.
     *
     * @param time a date object representing the time of interest.
     * @param locale the Locale whose calendar the underlying SimpleDateFormat should use.
     */
    public ASN1UTCTime(
        Date time,
        Locale locale)
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'", locale);

        dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

        this.contents = Strings.toByteArray(dateF.format(time));
    }

    ASN1UTCTime(byte[] contents)
    {
        if (contents.length < 2)
        {
            throw new IllegalArgumentException("UTCTime string too short");
        }
        this.contents = contents;
        if (!(isDigit(0) && isDigit(1)))
        {
            throw new IllegalArgumentException("illegal characters in UTCTime string");
        }
    }

    /**
     * Return the time as a date based on whatever a 2 digit year will return. For
     * standardised processing use getAdjustedDate().
     *
     * @return the resulting date
     * @exception ParseException if the date string cannot be parsed.
     */
    public Date getDate()
        throws ParseException
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmssz", LocaleUtil.EN_Locale);

        return dateF.parse(getTime());
    }

    /**
     * Return the time as an adjusted date
     * in the range of 1950 - 2049.
     *
     * @return a date in the range of 1950 to 2049.
     * @exception ParseException if the date string cannot be parsed.
     */
    public Date getAdjustedDate()
        throws ParseException
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz", LocaleUtil.EN_Locale);

        dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

        return dateF.parse(getAdjustedTime());
    }

    /**
     * Return the time - always in the form of
     *  YYMMDDhhmmssGMT(+hh:mm|-hh:mm).
     * <p>
     * Normally in a certificate we would expect "Z" rather than "GMT",
     * however adding the "GMT" means we can just use:
     * <pre>
     *     dateF = new SimpleDateFormat("yyMMddHHmmssz");
     * </pre>
     * To read in the time and get a date which is compatible with our local
     * time zone.
     * <p>
     * <b>Note:</b> In some cases, due to the local date processing, this
     * may lead to unexpected results. If you want to stick the normal
     * convention of 1950 to 2049 use the getAdjustedTime() method.
     */
    public String getTime()
    {
        String stime = Strings.fromByteArray(contents);

        //
        // standardise the format.
        //
        if (stime.indexOf('-') < 0 && stime.indexOf('+') < 0)
        {
            if (stime.length() == 11)
            {
                return stime.substring(0, 10) + "00GMT+00:00";
            }
            else
            {
                return stime.substring(0, 12) + "GMT+00:00";
            }
        }
        else
        {
            int index = stime.indexOf('-');
            if (index < 0)
            {
                index = stime.indexOf('+');
            }
            String d = stime;

            if (index == stime.length() - 3)
            {
                d += "00";
            }

            if (index == 10)
            {
                return d.substring(0, 10) + "00GMT" + d.substring(10, 13) + ":" + d.substring(13, 15);
            }
            else
            {
                return d.substring(0, 12) + "GMT" + d.substring(12, 15) + ":" +  d.substring(15, 17);
            }
        }
    }

    /**
     * Return a time string as an adjusted date with a 4 digit year. This goes
     * in the range of 1950 - 2049.
     */
    public String getAdjustedTime()
    {
        String   d = this.getTime();

        if (d.charAt(0) < '5')
        {
            return "20" + d;
        }
        else
        {
            return "19" + d;
        }
    }

    private boolean isDigit(int pos)
    {
        return contents.length > pos && contents[pos] >= '0' && contents[pos] <= '9';
    }

    final boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.UTC_TIME, contents);
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1UTCTime))
        {
            return false;
        }

        return Arrays.areEqual(contents, ((ASN1UTCTime)o).contents);
    }

    public int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    public String toString()
    {
      return Strings.fromByteArray(contents);
    }

    static ASN1UTCTime createPrimitive(byte[] contents)
    {
        // Parse path (ASN1InputStream / getInstance(byte[]) / implicit-tag decode): reject
        // structurally malformed content - non-digit or out-of-range fields, illegal lengths,
        // missing/garbage terminators - that the lenient constructor would otherwise accept and
        // that getDate() would turn into a nonsensical Date or fail on. Programmatic construction
        // (String/Date constructors) and DER re-encoding (toDERObject) do not pass through here.
        // The message deliberately omits the raw content (it may carry control characters).
        if (!ASN1TimeFormat.isValidUTCTime(contents))
        {
            throw new IllegalArgumentException("invalid UTCTime format");
        }
        return new ASN1UTCTime(contents);
    }

    ASN1Primitive toDERObject()
    {
        // BC stays lenient on read - non-DER UTCTime (e.g. missing seconds, '+hhmm' offset
        // in place of 'Z') is parsed without complaint. When emitting DER, however, the
        // primitive's contents must conform to X.690 sec. 11.8 / RFC 5280 sec. 4.1.2.5.1.
        // Setting Properties.ASN1_ALLOW_NON_DER_TIME to "false" enforces that on write to a
        // DEROutputStream (default "true"/unset preserves the historical pass-through).
        if (!Properties.isOverrideSet(Properties.ASN1_ALLOW_NON_DER_TIME, true) && !isDERUTCTime(contents))
        {
            throw new DEREncodingException("cannot emit UTCTime as DER: not in DER format (see Properties.ASN1_ALLOW_NON_DER_TIME)");
        }
        return this;
    }

    /**
     * DER UTCTime (X.690 sec. 11.8): the seconds element is always present and the value is
     * terminated by "Z", i.e. exactly "YYMMDDHHMMSSZ".
     */
    private static boolean isDERUTCTime(byte[] contents)
    {
        if (contents.length != 13 || contents[12] != 'Z')
        {
            return false;
        }
        for (int i = 0; i != 12; i++)
        {
            if (contents[i] < '0' || contents[i] > '9')
            {
                return false;
            }
        }
        return true;
    }
}
