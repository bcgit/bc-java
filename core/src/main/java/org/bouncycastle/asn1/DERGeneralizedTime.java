package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Date;

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
        if (contents[contents.length - 1] == 'Z')
        {
            if (!hasMinutes())
            {
                byte[] derTime = new byte[contents.length + 4];

                System.arraycopy(contents, 0, derTime, 0, contents.length - 1);
                System.arraycopy(Strings.toByteArray("0000Z"), 0, derTime, contents.length - 1, 5);

                return derTime;
            }
            else if (!hasSeconds())
            {
                byte[] derTime = new byte[contents.length + 2];

                System.arraycopy(contents, 0, derTime, 0, contents.length - 1);
                System.arraycopy(Strings.toByteArray("00Z"), 0, derTime, contents.length - 1, 3);

                return derTime;
            }
            else if (hasFractionalSeconds())
            {
                int ind = contents.length - 2;
                while (ind > 0 && contents[ind] == '0')
                {
                    ind--;
                }

                if (contents[ind] == '.')
                {
                    byte[] derTime = new byte[ind + 1];

                    System.arraycopy(contents, 0, derTime, 0, ind);
                    derTime[ind] = (byte)'Z';

                    return derTime;
                }
                else
                {
                    byte[] derTime = new byte[ind + 2];

                    System.arraycopy(contents, 0, derTime, 0, ind + 1);
                    derTime[ind + 1] = (byte)'Z';

                    return derTime;
                }
            }
            else
            {
                return contents;
            }
        }
        else
        {
            return contents; // TODO: is there a better way?
        }
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
