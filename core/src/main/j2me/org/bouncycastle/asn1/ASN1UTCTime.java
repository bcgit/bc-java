package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.util.Arrays;
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
     * @param explicit     true if the object is meant to be explicitly tagged false
     *                     otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1UTCTime instance, or null.
     */
    public static ASN1UTCTime getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1UTCTime)TYPE.getContextInstance(taggedObject, explicit);
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
        if (time.charAt(time.length() - 1) != 'Z')
        {
            // we accept this as a variation
            if (time.indexOf('-') < 0 && time.indexOf('+') < 0)
            {
                throw new IllegalArgumentException("time needs to be in format YYMMDDHHMMSSZ");
            }
        }
        this.contents = Strings.toByteArray(time);
    }

    /**
     * Base constructor from a java.util.date object
     * @param time the Date to build the time from.
     */
    public ASN1UTCTime(
        Date time)
    {
        this.contents = Strings.toByteArray(DateFormatter.toUTCDateString(time));
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
    {
        return DateFormatter.adjustedFromUTCDateString(contents);
    }

    /**
     * Return the time as an adjusted date
     * in the range of 1950 - 2049.
     *
     * @return a date in the range of 1950 to 2049.
     * @exception ParseException if the date string cannot be parsed.
     */
    public Date getAdjustedDate()
    {
         return DateFormatter.adjustedFromUTCDateString(contents);
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

    /**
     * Return the time.
     * @return The time string as it appeared in the encoded object.
     */
    public String getTimeString()
    {
        return Strings.fromByteArray(contents);
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
        return new ASN1UTCTime(contents);
    }
}
