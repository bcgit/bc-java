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


import com.github.gv2011.asn1.util.Arrays;
import com.github.gv2011.util.bytes.Bytes;

/**
 * Carrier class for DER encoding BMPString object.
 */
public class DERBMPString
    extends ASN1Primitive
    implements ASN1String
{
    private final char[] string;

    /**
     * return a BMP String from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBMPString instance, or null.
     */
    public static DERBMPString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERBMPString)
        {
            return (DERBMPString)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERBMPString)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a BMP String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     * @return a DERBMPString instance.
     */
    public static DERBMPString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBMPString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     * @param string the encoded BMP STRING to wrap.
     */
    DERBMPString(
        final Bytes string)
    {
        final char[]  cs = new char[string.size() / 2];

        for (int i = 0; i != cs.length; i++)
        {
            cs[i] = (char)((string.getByte(2 * i) << 8) | (string.getByte(2 * i + 1) & 0xff));
        }

        this.string = cs;
    }

    DERBMPString(final char[] string)
    {
        this.string = string;
    }

    /**
     * basic constructor
     * @param string a String to wrap as a BMP STRING.
     */
    public DERBMPString(
        final String   string)
    {
        this.string = string.toCharArray();
    }

    @Override
    public String getString()
    {
        return new String(string);
    }

    @Override
    public String toString()
    {
        return getString();
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    @Override
    protected boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof DERBMPString))
        {
            return false;
        }

        final DERBMPString  s = (DERBMPString)o;

        return Arrays.areEqual(string, s.string);
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length * 2) + (string.length * 2);
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.write(BERTags.BMP_STRING);
        out.writeLength(string.length * 2);

        for (int i = 0; i != string.length; i++)
        {
            final char c = string[i];

            out.write((byte)(c >> 8));
            out.write((byte)c);
        }
    }
}
