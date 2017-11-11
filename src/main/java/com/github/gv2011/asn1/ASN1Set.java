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
 * ASN.1 <code>SET</code> and <code>SET OF</code> constructs.
 * <p>
 * Note: This does not know which syntax the set is!
 * (The difference: ordering of SET elements or not ordering.)
 * <p>
 * DER form is always definite form length fields, while
 * BER support uses indefinite form.
 * <p>
 * The CER form support does not exist.
 * <p>
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
 * <h4>8.12 Encoding of a set-of value</h4>
 * <b>8.12.1</b> The encoding of a set-of value shall be constructed.
 * <p>
 * <b>8.12.2</b> The text of 8.10.2 applies:
 * <i>The contents octets shall consist of zero,
 * one or more complete encodings of data values from the type listed in
 * the ASN.1 definition.</i>
 * <p>
 * <b>8.12.3</b> The order of data values need not be preserved by
 * the encoding and subsequent decoding.
 *
 * <h3>9: Canonical encoding rules</h3>
 * <h4>9.1 Length forms</h4>
 * If the encoding is constructed, it shall employ the indefinite-length form.
 * If the encoding is primitive, it shall include the fewest length octets necessary.
 * [Contrast with 8.1.3.2 b).]
 * <h4>9.3 Set components</h4>
 * The encodings of the component values of a set value shall
 * appear in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * Additionally, for the purposes of determining the order in which
 * components are encoded when one or more component is an untagged
 * choice type, each untagged choice type is ordered as though it
 * has a tag equal to that of the smallest tag in that choice type
 * or any untagged choice types nested within.
 *
 * <h3>10: Distinguished encoding rules</h3>
 * <h4>10.1 Length forms</h4>
 * The definite form of length encoding shall be used,
 * encoded in the minimum number of octets.
 * [Contrast with 8.1.3.2 b).]
 * <h4>10.3 Set components</h4>
 * The encodings of the component values of a set value shall appear
 * in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * <blockquote>
 * NOTE &mdash; Where a component of the set is an untagged choice type,
 * the location of that component in the ordering will depend on
 * the tag of the choice component being encoded.
 * </blockquote>
 *
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.5 Set and sequence components with default value </h4>
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 * <h4>11.6 Set-of components </h4>
 * <p>
 * The encodings of the component values of a set-of value
 * shall appear in ascending order, the encodings being compared
 * as octet strings with the shorter components being padded at
 * their trailing end with 0-octets.
 * <blockquote>
 * NOTE &mdash; The padding octets are for comparison purposes only
 * and do not appear in the encodings.
 * </blockquote>
 */
public abstract class ASN1Set
    extends ASN1Primitive
    implements Iterable<ASN1Encodable>
{
    private Vector<Object> set = new Vector<>();
    private boolean isSorted = false;

    /**
     * return an ASN1Set from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Set instance, or null.
     */
    public static ASN1Set getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof ASN1Set)
        {
            return (ASN1Set)obj;
        }
        else if (obj instanceof ASN1SetParser)
        {
            return ASN1Set.getInstance(((ASN1SetParser)obj).toASN1Primitive());
        }
        else if (obj instanceof Bytes)
        {
            return ASN1Set.getInstance(ASN1Primitive.fromBytes((Bytes)obj));
        }
        else if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

            if (primitive instanceof ASN1Set)
            {
                return (ASN1Set)primitive;
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an ASN1 set from a tagged object. There is a special
     * case here, if an object appears to have been explicitly tagged on
     * reading but we were expecting it to be implicitly tagged in the
     * normal course of events it indicates that we lost the surrounding
     * set - so we need to add it back (this will happen if the tagged
     * object is a sequence that contains other sequences). If you are
     * dealing with implicitly tagged sets you really <b>should</b>
     * be using this method.
     *
     * @param obj the tagged object.
     * @param explicit true if the object is meant to be explicitly tagged
     *          false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *          be converted.
     * @return an ASN1Set instance.
     */
    public static ASN1Set getInstance(
        final ASN1TaggedObject    obj,
        final boolean             explicit)
    {
        if (explicit)
        {
            if (!obj.isExplicit())
            {
                throw new IllegalArgumentException("object implicit - explicit expected.");
            }

            return (ASN1Set)obj.getObject();
        }
        else
        {
            //
            // constructed object which appears to be explicitly tagged
            // and it's really implicit means we have to add the
            // surrounding set.
            //
            if (obj.isExplicit())
            {
                if (obj instanceof BERTaggedObject)
                {
                    return new BERSet(obj.getObject());
                }
                else
                {
                    return new DLSet(obj.getObject());
                }
            }
            else
            {
                if (obj.getObject() instanceof ASN1Set)
                {
                    return (ASN1Set)obj.getObject();
                }

                //
                // in this case the parser returns a sequence, convert it
                // into a set.
                //
                if (obj.getObject() instanceof ASN1Sequence)
                {
                    final ASN1Sequence s = (ASN1Sequence)obj.getObject();

                    if (obj instanceof BERTaggedObject)
                    {
                        return new BERSet(s.toArray());
                    }
                    else
                    {
                        return new DLSet(s.toArray());
                    }
                }
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    protected ASN1Set()
    {
    }

    /**
     * create a sequence containing one object
     * @param obj object to be added to the SET.
     */
    protected ASN1Set(
        final ASN1Encodable obj)
    {
        set.addElement(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     * @param v a vector of objects to make up the SET.
     * @param doSort true if should be sorted DER style, false otherwise.
     */
    protected ASN1Set(
        final ASN1EncodableVector v,
        final boolean                  doSort)
    {
        for (int i = 0; i != v.size(); i++)
        {
            set.addElement(v.get(i));
        }

        if (doSort)
        {
            sort();
        }
    }

    /*
     * create a sequence containing a vector of objects.
     */
    protected ASN1Set(
        final ASN1Encodable[]   array,
        final boolean doSort)
    {
        for (int i = 0; i != array.length; i++)
        {
            set.addElement(array[i]);
        }

        if (doSort)
        {
            sort();
        }
    }

    public Enumeration<Object> getObjects()
    {
        return set.elements();
    }

    /**
     * return the object at the set position indicated by index.
     *
     * @param index the set number (starting at zero) of the object
     * @return the object at the set position indicated by index.
     */
    public ASN1Encodable getObjectAt(
        final int index)
    {
        return (ASN1Encodable)set.elementAt(index);
    }

    /**
     * return the number of objects in this set.
     *
     * @return the number of objects in this set.
     */
    public int size()
    {
        return set.size();
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

    public ASN1SetParser parser()
    {
        final ASN1Set outer = this;

        return new ASN1SetParser()
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

    @Override
    public int hashCode()
    {
        final Enumeration<Object>             e = getObjects();
        int                     hashCode = size();

        while (e.hasMoreElements())
        {
            final Object o = getNext(e);
            hashCode *= 17;

            hashCode ^= o.hashCode();
        }

        return hashCode;
    }

    /**
     * Change current SET object to be encoded as {@link DERSet}.
     * This is part of Distinguished Encoding Rules form serialization.
     */
    @Override
    ASN1Primitive toDERObject()
    {
        if (isSorted)
        {
            final ASN1Set derSet = new DERSet();

            derSet.set = set;

            return derSet;
        }
        else
        {
            final Vector<Object> v = new Vector<>();

            for (int i = 0; i != set.size(); i++)
            {
                v.addElement(set.elementAt(i));
            }

            final ASN1Set derSet = new DERSet();

            derSet.set = v;

            derSet.sort();

            return derSet;
        }
    }

    /**
     * Change current SET object to be encoded as {@link DLSet}.
     * This is part of Direct Length form serialization.
     */
    @Override
    ASN1Primitive toDLObject()
    {
        final ASN1Set derSet = new DLSet();

        derSet.set = set;

        return derSet;
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1Set))
        {
            return false;
        }

        final ASN1Set   other = (ASN1Set)o;

        if (size() != other.size())
        {
            return false;
        }

        final Enumeration<Object> s1 = getObjects();
        final Enumeration<Object> s2 = other.getObjects();

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

    private ASN1Encodable getNext(final Enumeration<Object> e)
    {
        final ASN1Encodable encObj = (ASN1Encodable)e.nextElement();

        // unfortunately null was allowed as a substitute for DER null
        if (encObj == null)
        {
            return DERNull.INSTANCE;
        }

        return encObj;
    }

    /**
     * return true if a <= b (arrays are assumed padded with zeros).
     */
    private boolean lessThanOrEqual(
         final Bytes a,
         final Bytes b)
    {
        final int len = Math.min(a.size(), b.size());
        for (int i = 0; i != len; ++i)
        {
            if (a.getByte(i) != b.getByte(i))
            {
                return (a.getByte(i) & 0xff) < (b.getByte(i) & 0xff);
            }
        }
        return len == a.size();
    }

    private Bytes getDEREncoded(
        final ASN1Encodable obj)
    {
            return obj.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    protected void sort()
    {
        if (!isSorted)
        {
            isSorted = true;
            if (set.size() > 1)
            {
                boolean    swapped = true;
                int        lastSwap = set.size() - 1;

                while (swapped)
                {
                    int    index = 0;
                    int    swapIndex = 0;
                    Bytes a = getDEREncoded((ASN1Encodable)set.elementAt(0));

                    swapped = false;

                    while (index != lastSwap)
                    {
                        final Bytes b = getDEREncoded((ASN1Encodable)set.elementAt(index + 1));

                        if (lessThanOrEqual(a, b))
                        {
                            a = b;
                        }
                        else
                        {
                            final Object  o = set.elementAt(index);

                            set.setElementAt(set.elementAt(index + 1), index);
                            set.setElementAt(o, index + 1);

                            swapped = true;
                            swapIndex = index;
                        }

                        index++;
                    }

                    lastSwap = swapIndex;
                }
            }
        }
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
        return set.toString();
    }

    @Override
    public Iterator<ASN1Encodable> iterator()
    {
        return new Arrays.Iterator<>(toArray());
    }
}
