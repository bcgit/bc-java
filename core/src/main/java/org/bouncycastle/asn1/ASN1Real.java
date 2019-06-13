package org.bouncycastle.asn1;

import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;


public class ASN1Real extends ASN1Primitive {

    private byte[] content;


    public ASN1Real(
            Double value)
    {
        encodeContent(value);
    }


    public ASN1Real(
            byte[] content)
    {
        this.content = Arrays.clone(content);
    }

    /**
     * Get real type
     * @param obj byte[] or ASN1Real obj
     * @return  real instance
     */
    public static ASN1Real getInstance(
            Object obj)
    {
        if (obj == null || obj instanceof ASN1Real)
        {
            return (ASN1Real)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1Real)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Get the content represent double value
     *
     * {@link <a href="https://github.com/beanit/jasn1/blob/master/projects/jasn1/src/main/java/com/beanit/jasn1/ber/types/BerReal.java"></a>}
     *
     * @return double value
     */
    public double getValue()
    {
        if(content == null || content.length == 0)
        {
            return 0;
        }

        byte firstByte = this.content[0];

        if(content.length == 1)
        {
            if (firstByte == 0x40)
            {
                return Double.POSITIVE_INFINITY;
            }
            else if (firstByte == 0x41)
            {
                return  Double.NEGATIVE_INFINITY;
            }
            else
            {
                throw new IllegalArgumentException("Unexpected end of input real content");
            }
        }

        if ((firstByte & 0x80) != 0x80)
        {
            throw new IllegalArgumentException("Only binary REAL encoding is supported");
        }
        int sign =  ((firstByte & 0x40) == 0x40) ? -1 : 1;

        // Get exponent and mantissa
        byte[] byteCode = Arrays.copyOfRange(this.content, 1, this.content.length);

        int exponentLength = (firstByte & 0x03) + 1;
        if (exponentLength == 4) {
            exponentLength = byteCode[0];
            exponentLength++;
        }

        int exponent = 0;
        for (int i = 0; i < exponentLength; i++)
        {
            exponent |= byteCode[i] << (8 * (exponentLength - i - 1));
        }

        long mantissa = 0;
        for (int i = exponentLength; i < byteCode.length; i++)
        {
            mantissa |= (byteCode[i] & 0xFFL) << (8 * ( byteCode.length - i - 1));
        }

        return sign * mantissa * Math.pow(2, exponent);
    }

    void encode(
            ASN1OutputStream out)
            throws IOException
    {
        out.writeEncoded(BERTags.REAL, content);
    }

    /**
     * Encode double to real
     *
     * {@link <a herf="https://stackoverflow.com/questions/46962477/encoding-java-double-as-asn1-real-sign-mantissa-base-exponent"></a>}
     * @param value double value
     */
    private void encodeContent(
            Double value)
    {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        // explained in Annex C and Ch. 8.5 of X.690

        // we use binary encoding, with base 2 and F==0
        // F is only needed when encoding with base 8 or 16

        if (value == 0)
        {
            // no content
            content = new byte[0];
            return;
        }

        if (value == Double.POSITIVE_INFINITY)
        {
            buffer.write(0x40);
            return;
        }
        if (value == Double.NEGATIVE_INFINITY)
        {
            buffer.write(0x41);
            return;
        }

        try {
            // for demo, use real output as needed

            long bits = Double.doubleToRawLongBits(value);
            int signByte = (int) (bits >> (63 - 6)) & (1 << 6) | (1 << 7);
            // shift to the correct place to start with, and pre-add bit 8
            int exponent = ((int) (bits >> 52) & 0x7FF) - (1023 + 52);
            // don't need to box/unbox to do arithmetic
            long mantissa = (bits & 0xFFFFFFFFFFFFFL) | (1L << 52);
            // add the hidden bit
            while ((mantissa & 1) == 0)
            {
                mantissa >>= 1;
                exponent++;
            }
            // normalize
            byte[] exptbytes = BigInteger.valueOf(exponent).toByteArray();
            if (exptbytes.length < 3)
            {
                buffer.write(signByte | (exptbytes.length - 1));
            }
            else
            {
                buffer.write(signByte | 3);
                buffer.write(exptbytes.length);
            }
            // only the if branch is actually needed
            buffer.write(exptbytes);
            buffer.write(BigInteger.valueOf(mantissa).toByteArray());
        } catch (IOException e) {
            // memory operation do not cause error
        }
        this.content = buffer.toByteArray();
    }


    public int hashCode()
    {
        int value = 0;

        for (int i = 0; i != content.length; i++) {
            value ^= (content[i] & 0xff) << (i % 4);
        }

        return value;
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(content.length) + content.length;
    }


    boolean asn1Equals(
            ASN1Primitive o)
    {
        if (!(o instanceof ASN1Real))
        {
            return false;
        }

        ASN1Real other = (ASN1Real) o;

        return Arrays.areEqual(content, other.content);
    }

    /**
     * Get tag Content length
     * @return length of content
     */
    public int getLength()
    {
        return this.content.length;
    }

    public String toString()
    {
        return Double.toString(getValue());
    }
}
