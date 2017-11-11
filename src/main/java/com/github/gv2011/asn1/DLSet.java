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


import java.util.Enumeration;

/**
 * The DLSet encodes ASN.1 SET value without element ordering,
 * and always using definite length form.
 * <hr>
 * <h2>X.690</h2>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.11 Encoding of a set value </h4>
 * <b>8.11.1</b> The encoding of a set value shall be constructed
 * <p>
 * <b>8.11.2</b> The contents octets shall consist of the complete
 * encoding of a data value from each of the types listed in the
 * ASN.1 definition of the set type, in an order chosen by the sender,
 * unless the type was referenced with the keyword
 * <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
 * <p>
 * <b>8.11.3</b> The encoding of a data value may, but need not,
 * be present for a type which was referenced with the keyword
 * <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
 * <blockquote>
 * NOTE &mdash; The order of data values in a set value is not significant,
 * and places no constraints on the order during transfer
 * </blockquote>
 * <h3>9: Canonical encoding rules</h3>
 * <h4>9.3 Set components</h4>
 * The encodings of the component values of a set value shall
 * appear in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * Additionally, for the purposes of determining the order in which
 * components are encoded when one or more component is an untagged
 * choice type, each untagged choice type is ordered as though it
 * has a tag equal to that of the smallest tag in that choice type
 * or any untagged choice types nested within.
 * <h3>10: Distinguished encoding rules</h3>
 * <h4>10.3 Set components</h4>
 * The encodings of the component values of a set value shall appear
 * in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * <blockquote>
 * NOTE &mdash; Where a component of the set is an untagged choice type,
 * the location of that component in the ordering will depend on
 * the tag of the choice component being encoded.
 * </blockquote>
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.5 Set and sequence components with default value </h4>
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 */
public class DLSet
    extends ASN1Set
{
    private int bodyLength = -1;

    /**
     * create an empty set
     */
    public DLSet()
    {
    }

    /**
     * @param obj - a single object that makes up the set.
     */
    public DLSet(
        final ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * @param v - a vector of objects making up the set.
     */
    public DLSet(
        final ASN1EncodableVector v)
    {
        super(v, false);
    }

    /**
     * create a set from an array of objects.
     */
    public DLSet(
        final ASN1Encodable[] a)
    {
        super(a, false);
    }

    private int getBodyLength()
    {
        if (bodyLength < 0)
        {
            int length = 0;

            for (final Enumeration<?> e = getObjects(); e.hasMoreElements();)
            {
                final Object obj = e.nextElement();

                length += ((ASN1Encodable)obj).toASN1Primitive().toDLObject().encodedLength();
            }

            bodyLength = length;
        }

        return bodyLength;
    }

    @Override
    int encodedLength()
    {
        final int length = getBodyLength();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    /**
     * A note on the implementation:
     * <p>
     * As DL requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    @Override
    void encode(
        final ASN1OutputStream out)
    {
        final ASN1OutputStream dOut = out.getDLSubStream();
        final int length = getBodyLength();

        out.write(BERTags.SET | BERTags.CONSTRUCTED);
        out.writeLength(length);

        for (final Enumeration<?> e = getObjects(); e.hasMoreElements();)
        {
            final Object obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }
    }
}
