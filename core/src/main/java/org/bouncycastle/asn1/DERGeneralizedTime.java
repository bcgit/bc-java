package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER Generalized time object.
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
public class DERGeneralizedTime
    extends ASN1GeneralizedTime
{
    public DERGeneralizedTime(byte[] time)
    {
        super(time);
    }

    public DERGeneralizedTime(Date time)
    {
        super(time);
    }

    public DERGeneralizedTime(String time)
    {
        super(time);
    }

    private byte[] getDERTime()
    {
        if (contents[contents.length - 1] != 'Z')
        {
            return contents; // TODO: is there a better way?
        }

        // DER is YYYYMMDDHHMMSS[.fff]Z: seconds always present, a fraction only of a second, with no
        // trailing zeros and '.' as the separator. X.680 also allows the minutes and seconds to be left
        // out, and a fraction of whichever unit comes last, so that fraction is carried down into
        // minutes and seconds. It always comes out exact: a decimal fraction of 3600 or 60 seconds is
        // a decimal number of seconds.
        int end = contents.length - 1;
        int whole = hasMinutes() ? (hasSeconds() ? 14 : 12) : 10;
        int unitSeconds = (whole == 10) ? 3600 : (whole == 12) ? 60 : 1;

        int fractionStart = whole + 1;
        boolean hasFraction = whole < end && (contents[whole] == '.' || contents[whole] == ',');

        // The fraction is multiplied by unitSeconds one digit at a time from the right: the carry out of
        // the leading digit is the whole number of seconds, the digits left behind are the fraction of a
        // second. This is linear in the length of the fraction, which the encoding does not bound.
        int seconds = 0;
        byte[] secondsFraction = new byte[hasFraction ? end - fractionStart : 0];
        int fractionLength = secondsFraction.length;
        if (fractionLength != 0)
        {
            int carry = 0;
            for (int i = fractionLength - 1; i >= 0; i--)
            {
                int digit = contents[fractionStart + i] - '0';
                if (digit < 0 || digit > 9)
                {
                    throw new IllegalArgumentException("invalid fraction in GeneralizedTime");
                }
                int v = digit * unitSeconds + carry;
                secondsFraction[i] = (byte)('0' + v % 10);
                carry = v / 10;
            }
            seconds = carry;
            while (fractionLength > 0 && secondsFraction[fractionLength - 1] == '0')
            {
                fractionLength--;
            }
        }

        StringBuffer derTime = new StringBuffer(Strings.fromByteArray(Arrays.copyOfRange(contents, 0, whole)));
        if (whole == 10)
        {
            appendTwoDigits(derTime, seconds / 60);
            appendTwoDigits(derTime, seconds % 60);
        }
        else if (whole == 12)
        {
            appendTwoDigits(derTime, seconds);
        }
        if (fractionLength != 0)
        {
            derTime.append('.').append(Strings.fromByteArray(Arrays.copyOfRange(secondsFraction, 0, fractionLength)));
        }
        derTime.append('Z');

        return Strings.toByteArray(derTime.toString());
    }

    private static void appendTwoDigits(StringBuffer buf, int value)
    {
        if (value < 10)
        {
            buf.append('0');
        }
        buf.append(value);
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getDERTime().length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.GENERALIZED_TIME, getDERTime());
    }

    ASN1Primitive toDERObject()
    {
        return this;
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}
