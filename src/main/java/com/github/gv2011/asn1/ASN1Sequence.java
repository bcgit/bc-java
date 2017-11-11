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
import java.util.Iterator;
import java.util.Vector;

import com.github.gv2011.asn1.util.Arrays;
import com.github.gv2011.util.bytes.Bytes;

/**
 * ASN.1 <code>SEQUENCE</code> and <code>SEQUENCE OF</code> constructs.
 * <p>
 * DER form is always definite form length fields, while
 * BER support uses indefinite form.
 * <hr>
 * <p><b>X.690</b></p>
 * <p><b>8: Basic encoding rules</b></p>
 * <p><b>8.9 Encoding of a sequence value </b></p>
 * 8.9.1 The encoding of a sequence value shall be constructed.
 * <p>
 * <b>8.9.2</b> The contents octets shall consist of the complete
 * encoding of one data value from each of the types listed in
 * the ASN.1 definition of the sequence type, in the order of
 * their appearance in the definition, unless the type was referenced
 * with the keyword <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
 * </p><p>
 * <b>8.9.3</b> The encoding of a data value may, but need not,
 * be present for a type which was referenced with the keyword
 * <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
 * If present, it shall appear in the encoding at the point
 * corresponding to the appearance of the type in the ASN.1 definition.
 * </p><p>
 * <b>8.10 Encoding of a sequence-of value </b>
 * </p><p>
 * <b>8.10.1</b> The encoding of a sequence-of value shall be constructed.
 * <p>
 * <b>8.10.2</b> The contents octets shall consist of zero,
 * one or more complete encodings of data values from the type listed in
 * the ASN.1 definition.
 * <p>
 * <b>8.10.3</b> The order of the encodings of the data values shall be
 * the same as the order of the data values in the sequence-of value to
 * be encoded.
 * </p>
 * <p><b>9: Canonical encoding rules</b></p>
 * <p><b>9.1 Length forms</b></p>
 * If the encoding is constructed, it shall employ the indefinite-length form.
 * If the encoding is primitive, it shall include the fewest length octets necessary.
 * [Contrast with 8.1.3.2 b).]
 *
 * <p><b>11: Restrictions on BER employed by both CER and DER</b></p>
 * <p><b>11.5 Set and sequence components with default value</b></p>
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 */
public abstract class ASN1Sequence
    extends ASN1Primitive
    implements Iterable<ASN1Encodable>
{
    protected Vector<ASN1Encodable> seq = new Vector<>();

    /**
     * Return an ASN1Sequence from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Sequence instance, or null.
     */
    public static ASN1Sequence getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof ASN1Sequence)
        {
            return (ASN1Sequence)obj;
        }
        else if (obj instanceof ASN1SequenceParser)
        {
            return ASN1Sequence.getInstance(((ASN1SequenceParser)obj).toASN1Primitive());
        }
        else if (obj instanceof Bytes)
        {
            return ASN1Sequence.getInstance(fromBytes((Bytes)obj));
        }
        else if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

            if (primitive instanceof ASN1Sequence)
            {
                return (ASN1Sequence)primitive;
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an ASN1 sequence from a tagged object. There is a special
     * case here, if an object appears to have been explicitly tagged on
     * reading but we were expecting it to be implicitly tagged in the
     * normal course of events it indicates that we lost the surrounding
     * sequence - so we need to add it back (this will happen if the tagged
     * object is a sequence that contains other sequences). If you are
     * dealing with implicitly tagged sequences you really <b>should</b>
     * be using this method.
     *
     * @param obj the tagged object.
     * @param explicit true if the object is meant to be explicitly tagged,
     *          false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *          be converted.
     * @return an ASN1Sequence instance.
     */
    public static ASN1Sequence getInstance(
        final ASN1TaggedObject    obj,
        final boolean             explicit)
    {
        if (explicit)
        {
            if (!obj.isExplicit())
            {
                throw new IllegalArgumentException("object implicit - explicit expected.");
            }

            return ASN1Sequence.getInstance(obj.getObject().toASN1Primitive());
        }
        else
        {
            //
            // constructed object which appears to be explicitly tagged
            // when it should be implicit means we have to add the
            // surrounding sequence.
            //
            if (obj.isExplicit())
            {
                if (obj instanceof BERTaggedObject)
                {
                    return new BERSequence(obj.getObject());
                }
                else
                {
                    return new DLSequence(obj.getObject());
                }
            }
            else
            {
                if (obj.getObject() instanceof ASN1Sequence)
                {
                    return (ASN1Sequence)obj.getObject();
                }
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Create an empty sequence
     */
    protected ASN1Sequence()
    {
    }

    /**
     * Create a sequence containing one object
     * @param obj the object to be put in the SEQUENCE.
     */
    protected ASN1Sequence(
        final ASN1Encodable obj)
    {
        seq.addElement(obj);
    }

    /**
     * Create a sequence containing a vector of objects.
     * @param v the vector of objects to be put in the SEQUENCE
     */
    protected ASN1Sequence(
        final ASN1EncodableVector v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            seq.addElement(v.get(i));
        }
    }

    /*
     * Create a sequence containing a vector of objects.
     */
    protected ASN1Sequence(
        final ASN1Encodable[]   array)
    {
        for (int i = 0; i != array.length; i++)
        {
            seq.addElement(array[i]);
        }
    }

    public ASN1Encodable[] toArray()
    {
        final ASN1Encodable[] values = new ASN1Encodable[size()];

        for (int i = 0; i != size(); i++)
        {
            values[i] = getObjectAt(i);
        }

        return values;
    }

    public Enumeration<ASN1Encodable> getObjects()
    {
        return seq.elements();
    }

    public ASN1SequenceParser parser()
    {
        final ASN1Sequence outer = this;

        return new ASN1SequenceParser()
        {
            private final int max = size();

            private int index;

            @Override
            public ASN1Encodable readObject()
            {
                if (index == max)
                {
                    return null;
                }

                final ASN1Encodable obj = getObjectAt(index++);
                if (obj instanceof ASN1Sequence)
                {
                    return ((ASN1Sequence)obj).parser();
                }
                if (obj instanceof ASN1Set)
                {
                    return ((ASN1Set)obj).parser();
                }

                return obj;
            }

            @Override
            public ASN1Primitive getLoadedObject()
            {
                return outer;
            }

            @Override
            public ASN1Primitive toASN1Primitive()
            {
                return outer;
            }
        };
    }

    /**
     * Return the object at the sequence position indicated by index.
     *
     * @param index the sequence number (starting at zero) of the object
     * @return the object at the sequence position indicated by index.
     */
    public ASN1Encodable getObjectAt(
        final int index)
    {
        return seq.elementAt(index);
    }

    /**
     * Return the number of objects in this sequence.
     *
     * @return the number of objects in this sequence.
     */
    public int size()
    {
        return seq.size();
    }

    @Override
    public int hashCode()
    {
        @SuppressWarnings("rawtypes")
        final Enumeration             e = getObjects();
        int                     hashCode = size();

        while (e.hasMoreElements())
        {
            final Object o = getNext(e);
            hashCode *= 17;

            hashCode ^= o.hashCode();
        }

        return hashCode;
    }

    @SuppressWarnings("rawtypes")
    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1Sequence))
        {
            return false;
        }

        final ASN1Sequence   other = (ASN1Sequence)o;

        if (size() != other.size())
        {
            return false;
        }

        final Enumeration s1 = getObjects();
        final Enumeration s2 = other.getObjects();

        while (s1.hasMoreElements())
        {
            final ASN1Encodable obj1 = getNext(s1);
            final ASN1Encodable obj2 = getNext(s2);

            final ASN1Primitive o1 = obj1.toASN1Primitive();
            final ASN1Primitive o2 = obj2.toASN1Primitive();

            if (o1 == o2 || o1.equals(o2))
            {
                continue;
            }

            return false;
        }

        return true;
    }

    @SuppressWarnings("rawtypes")
    private ASN1Encodable getNext(final Enumeration e)
    {
        final ASN1Encodable encObj = (ASN1Encodable)e.nextElement();

        return encObj;
    }

    /**
     * Change current SEQUENCE object to be encoded as {@link DERSequence}.
     * This is part of Distinguished Encoding Rules form serialization.
     */
    @Override
    ASN1Primitive toDERObject()
    {
        final ASN1Sequence derSeq = new DERSequence();

        derSeq.seq = seq;

        return derSeq;
    }

    /**
     * Change current SEQUENCE object to be encoded as {@link DLSequence}.
     * This is part of Direct Length form serialization.
     */
    @Override
    ASN1Primitive toDLObject()
    {
        final ASN1Sequence dlSeq = new DLSequence();

        dlSeq.seq = seq;

        return dlSeq;
    }

    @Override
    boolean isConstructed()
    {
        return true;
    }

    @Override
    abstract void encode(ASN1OutputStream out);

    @Override
    public String toString()
    {
        return seq.toString();
    }

    @Override
    public Iterator<ASN1Encodable> iterator()
    {
        return new Arrays.Iterator<>(toArray());
    }
}
