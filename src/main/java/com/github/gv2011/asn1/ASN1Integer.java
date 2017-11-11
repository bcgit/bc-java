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


import static com.github.gv2011.util.bytes.ByteUtils.fromBigInteger;

import java.math.BigInteger;

import com.github.gv2011.util.bytes.Bytes;

/**
 * Class representing the ASN.1 INTEGER type.
 */
public class ASN1Integer
    extends ASN1Primitive
{
    private final Bytes bytes;

    /**
     * return an integer from the passed in object
     *
     * @param obj an ASN1Integer or an object that can be converted into one.
     * @throws IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Integer instance.
     */
    public static ASN1Integer getInstance(
        final Object obj)
    {
        if (obj == null || obj instanceof ASN1Integer)
        {
            return (ASN1Integer)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (ASN1Integer)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Integer from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     * @return an ASN1Integer instance.
     */
    public static ASN1Integer getInstance(
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1Integer)
        {
            return getInstance(o);
        }
        else
        {
            return new ASN1Integer(ASN1OctetString.getInstance(obj.getObject()).getOctets());
        }
    }

    public ASN1Integer(final long value){
      this(BigInteger.valueOf(value));
    }

    public ASN1Integer(final BigInteger value){
      this(fromBigInteger(value));
    }

    public ASN1Integer(final Bytes bytes){
      this.bytes = bytes;
    }

    public BigInteger getValue()
    {
        return new BigInteger(bytes.toByteArray());
    }

    /**
     * in some cases positive values get crammed into a space,
     * that's not quite big enough...
     * @return the BigInteger that results from treating this ASN.1 INTEGER as unsigned.
     */
    public BigInteger getPositiveValue()
    {
        return new BigInteger(1, bytes.toByteArray());
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.size()) + bytes.size();
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.INTEGER, bytes);
    }

    @Override
    public int hashCode()
    {
        int value = 0;

        for (int i = 0; i != bytes.size(); i++)
        {
            value ^= (bytes.getByte(i) & 0xff) << (i % 4);
        }

        return value;
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1Integer))
        {
            return false;
        }

        final ASN1Integer other = (ASN1Integer)o;

        return bytes.equals(other.bytes);
    }

    @Override
    public String toString()
    {
        return getValue().toString();
    }

}
