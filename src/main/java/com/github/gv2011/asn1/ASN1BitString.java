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


import static com.github.gv2011.util.bytes.ByteUtils.emptyBytes;
import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.ByteArrayOutputStream;

import java.io.InputStream;

import com.github.gv2011.asn1.util.io.Streams;
import com.github.gv2011.util.bytes.Bytes;

/**
 * Base class for BIT STRING objects
 */
public abstract class ASN1BitString
    extends ASN1Primitive
    implements ASN1String
{
    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    protected final Bytes      data;
    protected final int         padBits;

    /**
     * @param bitString an int containing the BIT STRING
     * @return the correct number of pad bits for a bit string defined in
     * a 32 bit constant
     */
    static protected int getPadBits(
        final int bitString)
    {
        int val = 0;
        for (int i = 3; i >= 0; i--)
        {
            //
            // this may look a little odd, but if it isn't done like this pre jdk1.2
            // JVM's break!
            //
            if (i != 0)
            {
                if ((bitString >> (i * 8)) != 0)
                {
                    val = (bitString >> (i * 8)) & 0xFF;
                    break;
                }
            }
            else
            {
                if (bitString != 0)
                {
                    val = bitString & 0xFF;
                    break;
                }
            }
        }

        if (val == 0)
        {
            return 0;
        }

        int bits = 1;

        while (((val <<= 1) & 0xFF) != 0)
        {
            bits++;
        }

        return 8 - bits;
    }

    /**
     * @param bitString an int containing the BIT STRING
     * @return the correct number of bytes for a bit string defined in
     * a 32 bit constant
     */
    static protected Bytes getBytes(final int bitString)
    {
        if (bitString == 0)
        {
            return emptyBytes();
        }

        int bytes = 4;
        for (int i = 3; i >= 1; i--)
        {
            if ((bitString & (0xFF << (i * 8))) != 0)
            {
                break;
            }
            bytes--;
        }

        final byte[] result = new byte[bytes];
        for (int i = 0; i < bytes; i++)
        {
            result[i] = (byte) ((bitString >> (i * 8)) & 0xFF);
        }

        return newBytes(result);
    }

    /**
     * Base constructor.
     *
     * @param data the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    public ASN1BitString(
        final Bytes  data,
        final int     padBits)
    {
        if (data == null)
        {
            throw new NullPointerException("data cannot be null");
        }
        if (data.size() == 0 && padBits != 0)
        {
            throw new IllegalArgumentException("zero length data with non-zero pad bits");
        }
        if (padBits > 7 || padBits < 0)
        {
            throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
        }

        this.data = data;
        this.padBits = padBits;
    }

    /**
     * Return a String representation of this BIT STRING
     *
     * @return a String representation.
     */
    @Override
    public String getString()
    {
        final StringBuffer          buf = new StringBuffer("#");
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final ASN1OutputStream      aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(this);

        final byte[]    string = bOut.toByteArray();

        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }

        return buf.toString();
    }

    /**
     * @return the value of the bit string as an int (truncating if necessary)
     */
    public int intValue()
    {
        int value = 0;
        Bytes string = data;

        if (padBits > 0 && data.size() <= 4)
        {
            string = derForm(data, padBits);
        }

        for (int i = 0; i != string.size() && i != 4; i++)
        {
            value |= (string.getByte(i) & 0xff) << (8 * i);
        }

        return value;
    }

    /**
     * Return the octets contained in this BIT STRING, checking that this BIT STRING really
     * does represent an octet aligned string. Only use this method when the standard you are
     * following dictates that the BIT STRING will be octet aligned.
     *
     * @return a copy of the octet aligned data.
     */
    public Bytes getOctets()
    {
        if (padBits != 0)
        {
            throw new IllegalStateException("attempt to get non-octet aligned data from BIT STRING");
        }

        return data;
    }

    public Bytes getBytes()
    {
        return derForm(data, padBits);
    }

    public int getPadBits()
    {
        return padBits;
    }

    @Override
    public String toString()
    {
        return getString();
    }

    @Override
    public int hashCode()
    {
        return padBits ^ this.getBytes().hashCode();
    }

    @Override
    protected boolean asn1Equals(
        final ASN1Primitive  o)
    {
        if (!(o instanceof ASN1BitString))
        {
            return false;
        }

        final ASN1BitString other = (ASN1BitString)o;

        return padBits == other.padBits && this.getBytes().equals(other.getBytes());
    }

    protected static Bytes derForm(final Bytes data, final int padBits)
    {
        // DER requires pad bits be zero
        if (padBits > 0){
          final byte[] rv = data.toByteArray();
          rv[data.size() - 1] &= 0xff << padBits;
          return newBytes(rv);
        }
        else return data;
    }

    static ASN1BitString fromInputStream(final int length, final InputStream stream)
    {
        if (length < 1)
        {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }

        final int padBits = call(stream::read);
        final byte[] data = new byte[length - 1];

        if (data.length != 0)
        {
            if (Streams.readFully(stream, data) != data.length)
            {
                throw new ASN1Exception("EOF encountered in middle of BIT STRING");
            }

            if (padBits > 0 && padBits < 8)
            {
                if (data[data.length - 1] != (byte)(data[data.length - 1] & (0xff << padBits)))
                {
                    return new DLBitString(newBytes(data), padBits);
                }
            }
        }

        return new DERBitString(newBytes(data), padBits);
    }

    public ASN1Primitive getLoadedObject()
    {
        return toASN1Primitive();
    }

    @Override
    ASN1Primitive toDERObject()
    {
        return new DERBitString(data, padBits);
    }

    @Override
    ASN1Primitive toDLObject()
    {
        return new DLBitString(data, padBits);
    }

    @Override
    abstract void encode(ASN1OutputStream out);
}
