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
 * DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public final class DERVisibleString extends ASN1PrimitiveBytes implements ASN1String {

    /**
     * Return a Visible String from the passed in object.
     *
     * @param obj a DERVisibleString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERVisibleString instance, or null
     */
    public static DERVisibleString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERVisibleString)
        {
            return (DERVisibleString)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERVisibleString)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Visible String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERVisibleString instance, or null
     */
    public static DERVisibleString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERVisibleString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERVisibleString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    DERVisibleString(final Bytes string){
      super(string);
    }

    public DERVisibleString(final String string){
      this(Strings.toByteArray(string));
    }

    @Override
    public String getString(){
      return Strings.fromByteArray(string);
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
        out.writeEncoded(BERTags.VISIBLE_STRING, string);
    }

}
