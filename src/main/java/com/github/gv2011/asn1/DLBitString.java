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


import static com.github.gv2011.util.bytes.ByteUtils.newBytes;

import java.io.IOException;

import com.github.gv2011.util.bytes.Bytes;

/**
 * A Definite length BIT STRING
 */
public class DLBitString
    extends ASN1BitString
{
    /**
     * return a Bit String that can be definite-length encoded from the passed in object.
     *
     * @param obj a DL or DER BitString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1BitString instance, or null.
     */
    public static ASN1BitString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DLBitString)
        {
            return (DLBitString)obj;
        }
        if (obj instanceof DERBitString)
        {
            return (DERBitString)obj;
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Bit String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1BitString instance, or null.
     */
    public static ASN1BitString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DLBitString)
        {
            return getInstance(o);
        }
        else
        {
            return fromOctetString(((ASN1OctetString)o).getOctets());
        }
    }

    protected DLBitString(
        final byte    data,
        final int     padBits)
    {
        this(newBytes(data), padBits);
    }

    /**
     * @param data the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    public DLBitString(
        final Bytes  data,
        final int     padBits)
    {
        super(data, padBits);
    }

    public DLBitString(
        final Bytes  data)
    {
        this(data, 0);
    }

    public DLBitString(
        final int value)
    {
        super(getBytes(value), getPadBits(value));
    }

    public DLBitString(
        final ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(data.size() + 1) + data.size() + 1;
    }

    @Override
    void encode(
        final ASN1OutputStream  out)
    {
        final byte[] string = data.toByteArray();
        final byte[] bytes = new byte[string.length + 1];

        bytes[0] = (byte)getPadBits();
        System.arraycopy(string, 0, bytes, 1, bytes.length - 1);

        out.writeEncoded(BERTags.BIT_STRING, newBytes(bytes));
    }

    static DLBitString fromOctetString(final Bytes bytes)
    {
        if (bytes.size() < 1){throw new IllegalArgumentException("truncated BIT STRING detected");}

        final int padBits = bytes.get(0);
        return new DLBitString(bytes.subList(1), padBits);
    }
}
