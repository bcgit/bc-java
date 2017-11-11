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


import com.github.gv2011.util.bytes.Bytes;

/**
 * A NULL object - use DERNull.INSTANCE for populating structures.
 */
public abstract class ASN1Null
    extends ASN1Primitive
{
    /**
     * Return an instance of ASN.1 NULL from the passed in object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1Null} object
     * <li> a byte[] containing ASN.1 NULL object
     * </ul>
     * </p>
     *
     * @param o object to be converted.
     * @return an instance of ASN1Null, or null.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Null getInstance(final Object o)
    {
        if (o instanceof ASN1Null)
        {
            return (ASN1Null)o;
        }

        if (o != null)
        {
            try
            {
                return ASN1Null.getInstance(ASN1Primitive.fromBytes((Bytes)o));
            }
            catch (final ClassCastException e)
            {
                throw new IllegalArgumentException("unknown object in getInstance(): " + o.getClass().getName());
            }
        }

        return null;
    }

    @Override
    public int hashCode()
    {
        return -1;
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1Null))
        {
            return false;
        }

        return true;
    }

    @Override
    abstract void encode(ASN1OutputStream out);

    @Override
    public String toString()
    {
         return "NULL";
    }
}
