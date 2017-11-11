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


import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

/**
 * DER IA5String object - this is an ascii string.
 */
public class DERIA5String
    extends ASN1Primitive
    implements ASN1String
{
    private final Bytes  string;

    /**
     * return a IA5 string from the passed in object
     *
     * @param obj a DERIA5String or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERIA5String instance, or null.
     */
    public static DERIA5String getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERIA5String)
        {
            return (DERIA5String)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERIA5String)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an IA5 String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERIA5String instance, or null.
     */
    public static DERIA5String getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERIA5String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERIA5String(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * basic constructor - with bytes.
     * @param string the byte encoding of the characters making up the string.
     */
    DERIA5String(
        final Bytes   string)
    {
        this.string = string;
    }

    /**
     * basic constructor - without validation.
     * @param string the base string to use..
     */
    public DERIA5String(
        final String   string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in an IA5String.
     */
    public DERIA5String(
        final String   string,
        final boolean  validate)
    {
        if (string == null)
        {
            throw new NullPointerException("string cannot be null");
        }
        if (validate && !isIA5String(string))
        {
            throw new IllegalArgumentException("string contains illegal characters");
        }

        this.string = Strings.toByteArray(string);
    }

    @Override
    public String getString()
    {
        return Strings.fromByteArray(string);
    }

    @Override
    public String toString()
    {
        return getString();
    }

    public Bytes getOctets()
    {
        return string;
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.size()) + string.size();
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.IA5_STRING, string);
    }

    @Override
    public int hashCode()
    {
        return string.hashCode();
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof DERIA5String))
        {
            return false;
        }

        final DERIA5String  s = (DERIA5String)o;

        return string.equals(s.string);
    }

    /**
     * return true if the passed in String can be represented without
     * loss as an IA5String, false otherwise.
     *
     * @param str the string to check.
     * @return true if character set in IA5String set, false otherwise.
     */
    public static boolean isIA5String(
        final String  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            final char    ch = str.charAt(i);

            if (ch > 0x007f)
            {
                return false;
            }
        }

        return true;
    }
}
