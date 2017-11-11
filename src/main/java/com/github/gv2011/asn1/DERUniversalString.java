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


import java.io.ByteArrayOutputStream;

import com.github.gv2011.util.bytes.Bytes;

/**
 * DER UniversalString object.
 */
public final class DERUniversalString
    extends ASN1PrimitiveBytes
    implements ASN1String
{
    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * return a Universal String from the passed in object.
     *
     * @param obj a DERUniversalString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERUniversalString instance, or null
     */
    public static DERUniversalString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERUniversalString)
        {
            return (DERUniversalString)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERUniversalString)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Universal String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERUniversalString instance, or null
     */
    public static DERUniversalString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERUniversalString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERUniversalString(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     *
     * @param string the byte encoding of the string to be carried in the UniversalString object,
     */
    public DERUniversalString(final Bytes string){
      super(string);
    }

    @Override
    public String getString()
    {
        final StringBuffer    buf = new StringBuffer("#");
        final ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        final ASN1OutputStream            aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(this);

        final byte[]    string = bOut.toByteArray();

        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }

        return buf.toString();
    }

    @Override
    public String toString()
    {
        return getString();
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.UNIVERSAL_STRING, getOctets());
    }

}
