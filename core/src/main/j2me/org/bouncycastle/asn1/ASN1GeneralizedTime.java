package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Base class representing the ASN.1 GeneralizedTime type.
 * <p>
 * The main difference between these and UTC time is a 4 digit year.
 * </p>
 * <p>
 * One second resolution date+time on UTC timezone (Z)
 * with 4 digit year (valid from 0001 to 9999).
 * </p><p>
 * Timestamp format is:  yyyymmddHHMMSS'Z'
 * </p><p>
 * <h2>X.690</h2>
 * This is what is called "restricted string",
 * and it uses ASCII characters to encode digits and supplemental data.
 *
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.7 GeneralizedTime </h4>
 * <p>
 * <b>11.7.1</b> The encoding shall terminate with a "Z",
 * as described in the ITU-T Rec. X.680 | ISO/IEC 8824-1 clause on
 * GeneralizedTime.
 * </p><p>
 * <b>11.7.2</b> The seconds element shall always be present.
 * </p>
 * <p>
 * <b>11.7.3</b> The fractional-seconds elements, if present,
 * shall omit all trailing zeros; if the elements correspond to 0,
 * they shall be wholly omitted, and the decimal point element also
 * shall be omitted.
 */
public class ASN1GeneralizedTime
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1GeneralizedTime.class, BERTags.GENERALIZED_TIME)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * return a generalized time from the passed in object
     *
     * @param obj an ASN1GeneralizedTime or an object that can be converted into one.
     * @return an ASN1GeneralizedTime instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1GeneralizedTime getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof ASN1GeneralizedTime)
        {
            return (ASN1GeneralizedTime)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1GeneralizedTime)
            {
                return (ASN1GeneralizedTime)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1GeneralizedTime)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Generalized Time object from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want
     * @param explicit     true if the object is meant to be explicitly tagged false
     *                     otherwise.
     * @return an ASN1GeneralizedTime instance.
     * @throws IllegalArgumentException if the tagged object cannot be converted.
     */
    public static ASN1GeneralizedTime getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1GeneralizedTime)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    /**
     * The correct format for this is YYYYMMDDHHMMSS[.f]Z, or without the Z
     * for local time, or Z|[+|-]HHMM on the end, for difference between local
     * time and UTC time. The fractional second amount f must consist of at
     * least one number with trailing zeroes removed.
     *
     * @param time the time string.
     * @throws IllegalArgumentException if String is an illegal format.
     */
    public ASN1GeneralizedTime(
        String time)
    {
        char last = time.charAt(time.length() - 1);
        if (last != 'Z' && !(last >= 0 && last <= '9'))
        {
            if (time.indexOf('-') < 0 && time.indexOf('+') < 0)
            {
                throw new IllegalArgumentException("time needs to be in format YYYYMMDDHHMMSS[.f]Z or YYYYMMDDHHMMSS[.f][+-]HHMM");
            }
        }

        this.contents = Strings.toByteArray(time);
    }

    /**
     * base constructer from a java.util.date object
     */
    public ASN1GeneralizedTime(
        Date time)
    {
        this.contents = Strings.toByteArray(DateFormatter.getGeneralizedTimeDateString(time, false));
    }

    protected ASN1GeneralizedTime(Date date, boolean includeMillis)
    {
        this.contents = Strings.toByteArray(DateFormatter.getGeneralizedTimeDateString(date, true));
    }
    
    ASN1GeneralizedTime(
        byte[] bytes)
    {
        if (bytes.length < 4)
        {
            throw new IllegalArgumentException("GeneralizedTime string too short");
        }
        this.contents = bytes;

        if (!(isDigit(0) && isDigit(1) && isDigit(2) && isDigit(3)))
        {
            throw new IllegalArgumentException("illegal characters in GeneralizedTime string");
        }
    }

    /**
     * Return the time.
     *
     * @return The time string as it appeared in the encoded object.
     */
    public String getTimeString()
    {
        return Strings.fromByteArray(contents);
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
     *
     * @return a String representation of the time.
     */
    public String getTime()
    {
        String stime = Strings.fromByteArray(contents);

        //
        // standardise the format.
        //
        if (stime.charAt(stime.length() - 1) == 'Z')
        {
            return stime.substring(0, stime.length() - 1) + "GMT+00:00";
        }
        else
        {
            int signPos = stime.length() - 6;
            char sign = stime.charAt(signPos);
            if ((sign == '-' || sign == '+') && stime.indexOf("GMT") == signPos - 3)
            {
                // already a GMT string!
                return stime;
            }

            signPos = stime.length() - 5;
            sign = stime.charAt(signPos);
            if (sign == '-' || sign == '+')
            {
                return stime.substring(0, signPos)
                    + "GMT"
                    + stime.substring(signPos, signPos + 3)
                    + ":"
                    + stime.substring(signPos + 3);
            }

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
        return stime + calculateGMTOffset(stime);
    }

    private String calculateGMTOffset(String stime)
    {
        String sign = "+";
        TimeZone timeZone = TimeZone.getDefault();
        int offset = timeZone.getRawOffset();
        if (offset < 0)
        {
            sign = "-";
            offset = -offset;
        }
        int hours = offset / (60 * 60 * 1000);
        int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

//        try
//        {
//            if (timeZone.useDaylightTime())
//            {
//                if (hasFractionalSeconds())
//                {
//                    stime = pruneFractionalSeconds(stime);
//                }
//                SimpleDateFormat dateF = calculateGMTDateFormat();
//                if (timeZone.inDaylightTime(
//                    dateF.parse(stime + "GMT" + sign + convert(hours) + ":" + convert(minutes))))
//                {
//                    hours += sign.equals("+") ? 1 : -1;
//                }
//            }
//        }
//        catch (ParseException e)
//        {
//            // we'll do our best and ignore daylight savings
//        }

        return "GMT" + sign + convert(hours) + ":" + convert(minutes);
    }

    private String pruneFractionalSeconds(String origTime)
    {
        // java misinterprets extra digits as being milliseconds...
        String frac = origTime.substring(14);
        int index;
        for (index = 1; index < frac.length(); index++)
        {
            char ch = frac.charAt(index);
            if (!('0' <= ch && ch <= '9'))
            {
                break;
            }
        }

        if (index - 1 > 3)
        {
            frac = frac.substring(0, 4) + frac.substring(index);
            origTime = origTime.substring(0, 14) + frac;
        }
        else if (index - 1 == 1)
        {
            frac = frac.substring(0, index) + "00" + frac.substring(index);
            origTime = origTime.substring(0, 14) + frac;
        }
        else if (index - 1 == 2)
        {
            frac = frac.substring(0, index) + "0" + frac.substring(index);
            origTime = origTime.substring(0, 14) + frac;
        }

        return origTime;
    }

    private String convert(int time)
    {
        if (time < 10)
        {
            return "0" + time;
        }

        return Integer.toString(time);
    }

    public Date getDate()
    {
        return DateFormatter.fromGeneralizedTimeString(contents);
    }

    protected boolean hasFractionalSeconds()
    {
        for (int i = 0; i != contents.length; i++)
        {
            if (contents[i] == '.')
            {
                if (i == 14)
                {
                    return true;
                }
            }
        }
        return false;
    }

    protected boolean hasSeconds()
    {
        return isDigit(12) && isDigit(13);
    }

    protected boolean hasMinutes()
    {
        return isDigit(10) && isDigit(11);
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

    void encode(ASN1OutputStream out, boolean withTag)
        throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.GENERALIZED_TIME, contents);
    }

    ASN1Primitive toDERObject()
    {
        return new DERGeneralizedTime(contents);
    }

    ASN1Primitive toDLObject()
    {
        return new DERGeneralizedTime(contents);
    }

    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof ASN1GeneralizedTime))
        {
            return false;
        }

        return Arrays.areEqual(contents, ((ASN1GeneralizedTime)o).contents);
    }

    public int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    static ASN1GeneralizedTime createPrimitive(byte[] contents)
    {
        return new ASN1GeneralizedTime(contents);
    }
}
