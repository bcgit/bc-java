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
 * Carrier class for a DER encoding GeneralString
 */
public class DERGeneralString
    extends ASN1Primitive
    implements ASN1String
{
    private final Bytes string;

    /**
     * return a GeneralString from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBMPString instance, or null.
     */
    public static DERGeneralString getInstance(
        final Object obj)
    {
        if (obj == null || obj instanceof DERGeneralString)
        {
            return (DERGeneralString) obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERGeneralString)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }

    /**
     * return a GeneralString from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     * @return a DERGeneralString instance.
     */
    public static DERGeneralString getInstance(
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERGeneralString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERGeneralString(((ASN1OctetString)o).getOctets());
        }
    }

    DERGeneralString(final Bytes string)
    {
        this.string = string;
    }

    /**
     * Construct a GeneralString from the passed in String.
     *
     * @param string the string to be contained in this object.
     */
    public DERGeneralString(final String string)
    {
        this.string = Strings.toByteArray(string);
    }

    /**
     * Return a Java String representation of our contained String.
     *
     * @return a Java String representing our contents.
     */
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

    /**
     * Return a byte array representation of our contained String.
     *
     * @return a byte array representing our contents.
     */
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
    void encode(final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.GENERAL_STRING, string);
    }

    @Override
    public int hashCode()
    {
        return string.hashCode();
    }

    @Override
    boolean asn1Equals(final ASN1Primitive o)
    {
        if (!(o instanceof DERGeneralString))
        {
            return false;
        }
        final DERGeneralString s = (DERGeneralString)o;

        return string.equals(s.string);
    }
}
