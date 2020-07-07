package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.bouncycastle.util.Arrays;

/**
 * ASN.1 <code>SET</code> and <code>SET OF</code> constructs.
 * <p>
 * Note: This does not know which syntax the set is!
 * (The difference: ordering of SET elements or not ordering.)
 * </p><p>
 * DER form is always definite form length fields, while
 * BER support uses indefinite form.
 * </p><p>
 * The CER form support does not exist.
 * </p><p>
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
 * </p><p>
 * <b>8.11.3</b> The encoding of a data value may, but need not,
 * be present for a type which was referenced with the keyword
 * <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
 * <blockquote>
 * NOTE &mdash; The order of data values in a set value is not significant,
 * and places no constraints on the order during transfer
 * </blockquote>
 * <h4>8.12 Encoding of a set-of value</h4>
 * <p>
 * <b>8.12.1</b> The encoding of a set-of value shall be constructed.
 * </p><p>
 * <b>8.12.2</b> The text of 8.10.2 applies:
 * <i>The contents octets shall consist of zero,
 * one or more complete encodings of data values from the type listed in
 * the ASN.1 definition.</i>
 * </p><p>
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
    implements org.bouncycastle.util.Iterable<ASN1Encodable>
{
    protected final ASN1Encodable[] elements;
    protected final boolean isSorted;

    /**
     * return an ASN1Set from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Set instance, or null.
     */
    public static ASN1Set getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Set)
        {
            return (ASN1Set)obj;
        }
        else if (obj instanceof ASN1SetParser)
        {
            return ASN1Set.getInstance(((ASN1SetParser)obj).toASN1Primitive());
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return ASN1Set.getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct set from byte[]: " + e.getMessage());
            }
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

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
     * @param taggedObject the tagged object.
     * @param explicit true if the object is meant to be explicitly tagged
     *          false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *          be converted.
     * @return an ASN1Set instance.
     */
    public static ASN1Set getInstance(
        ASN1TaggedObject    taggedObject,
        boolean             explicit)
    {
        if (explicit)
        {
            if (!taggedObject.isExplicit())
            {
                throw new IllegalArgumentException("object implicit - explicit expected.");
            }

            return getInstance(taggedObject.getObject());
        }

        ASN1Primitive o = taggedObject.getObject();

        /*
         * constructed object which appears to be explicitly tagged and it's really implicit means
         * we have to add the surrounding set.
         */
        if (taggedObject.isExplicit())
        {
            if (taggedObject instanceof BERTaggedObject)
            {
                return new BERSet(o);
            }

            return new DLSet(o);
        }

        if (o instanceof ASN1Set)
        {
            ASN1Set s = (ASN1Set)o;

            if (taggedObject instanceof BERTaggedObject)
            {
                return s;
            }

            return (ASN1Set)s.toDLObject();
        }

        /*
         * in this case the parser returns a sequence, convert it into a set.
         */
        if (o instanceof ASN1Sequence)
        {
            ASN1Sequence s = (ASN1Sequence)o;

            // NOTE: Will force() a LazyEncodedSequence
            ASN1Encodable[] elements = s.toArrayInternal();

            if (taggedObject instanceof BERTaggedObject)
            {
                return new BERSet(false, elements);
            }

            return new DLSet(false, elements);
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + taggedObject.getClass().getName());
    }

    protected ASN1Set()
    {
        this.elements = ASN1EncodableVector.EMPTY_ELEMENTS;
        this.isSorted = true;
    }

    /**
     * Create a SET containing one object
     * @param element object to be added to the SET.
     */
    protected ASN1Set(ASN1Encodable element)
    {
        if (null == element)
        {
            throw new NullPointerException("'element' cannot be null");
        }

        this.elements = new ASN1Encodable[]{ element };
        this.isSorted = true;
    }

    /**
     * Create a SET containing a vector of objects.
     * @param elementVector a vector of objects to make up the SET.
     * @param doSort true if should be sorted DER style, false otherwise.
     */
    protected ASN1Set(ASN1EncodableVector elementVector, boolean doSort)
    {
        if (null == elementVector)
        {
            throw new NullPointerException("'elementVector' cannot be null");
        }

        ASN1Encodable[] tmp;
        if (doSort && elementVector.size() >= 2)
        {
            tmp = elementVector.copyElements();
            sort(tmp);
        }
        else
        {
            tmp = elementVector.takeElements();
        }

        this.elements = tmp;
        this.isSorted = doSort || tmp.length < 2;
    }

    /**
     * Create a SET containing an array of objects.
     * @param elements an array of objects to make up the SET.
     * @param doSort true if should be sorted DER style, false otherwise.
     */
    protected ASN1Set(ASN1Encodable[] elements, boolean doSort)
    {
        if (Arrays.isNullOrContainsNull(elements))
        {
            throw new NullPointerException("'elements' cannot be null, or contain null");
        }

        ASN1Encodable[] tmp = ASN1EncodableVector.cloneElements(elements);
        if (doSort && tmp.length >= 2)
        {
            sort(tmp);
        }

        this.elements = tmp;
        this.isSorted = doSort || tmp.length < 2;
    }

    ASN1Set(boolean isSorted, ASN1Encodable[] elements)
    {
        this.elements = elements;
        this.isSorted = isSorted || elements.length < 2;
    }

    public Enumeration getObjects()
    {
        return new Enumeration()
        {
            private int pos = 0;

            public boolean hasMoreElements()
            {
                return pos < elements.length;
            }

            public Object nextElement()
            {
                if (pos < elements.length)
                {
                    return elements[pos++];
                }
                throw new NoSuchElementException();
            }
        };
    }

    /**
     * return the object at the set position indicated by index.
     *
     * @param index the set number (starting at zero) of the object
     * @return the object at the set position indicated by index.
     */
    public ASN1Encodable getObjectAt(int index)
    {
        return elements[index];
    }

    /**
     * return the number of objects in this set.
     *
     * @return the number of objects in this set.
     */
    public int size()
    {
        return elements.length;
    }

    public ASN1Encodable[] toArray()
    {
        return ASN1EncodableVector.cloneElements(elements);
    }

    public ASN1SetParser parser()
    {
        final int count = size();

        return new ASN1SetParser()
        {
            private int pos = 0;

            public ASN1Encodable readObject() throws IOException
            {
                if (count == pos)
                {
                    return null;
                }

                ASN1Encodable obj = elements[pos++];
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

            public ASN1Primitive getLoadedObject()
            {
                return ASN1Set.this;
            }

            public ASN1Primitive toASN1Primitive()
            {
                return ASN1Set.this;
            }
        };
    }

    public int hashCode()
    {
//        return Arrays.hashCode(elements);
        int i = elements.length;
        int hc = i + 1;

        // NOTE: Order-independent contribution of elements to avoid sorting
        while (--i >= 0)
        {
            hc += elements[i].toASN1Primitive().hashCode();
        }

        return hc;
    }

    /**
     * Change current SET object to be encoded as {@link DERSet}.
     * This is part of Distinguished Encoding Rules form serialization.
     */
    ASN1Primitive toDERObject()
    {
        ASN1Encodable[] tmp;
        if (isSorted)
        {
            tmp = elements;
        }
        else
        {
            tmp = (ASN1Encodable[])elements.clone();
            sort(tmp);
        }

        return new DERSet(true, tmp);
    }

    /**
     * Change current SET object to be encoded as {@link DLSet}.
     * This is part of Direct Length form serialization.
     */
    ASN1Primitive toDLObject()
    {
        return new DLSet(isSorted, elements);
    }

    boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1Set))
        {
            return false;
        }

        ASN1Set that = (ASN1Set)other;

        int count = this.size();
        if (that.size() != count)
        {
            return false;
        }

        DERSet dis = (DERSet)this.toDERObject();
        DERSet dat = (DERSet)that.toDERObject();

        for (int i = 0; i < count; ++i)
        {
            ASN1Primitive p1 = dis.elements[i].toASN1Primitive();
            ASN1Primitive p2 = dat.elements[i].toASN1Primitive();

            if (p1 != p2 && !p1.asn1Equals(p2))
            {
                return false;
            }
        }

        return true;
    }

    boolean isConstructed()
    {
        return true;
    }

    abstract void encode(ASN1OutputStream out, boolean withTag) throws IOException;

    public String toString() 
    {
        int count = size();
        if (0 == count)
        {
            return "[]";
        }

        StringBuffer sb = new StringBuffer();
        sb.append('[');
        for (int i = 0;;)
        {
            sb.append(elements[i]);
            if (++i >= count)
            {
                break;
            }
            sb.append(", ");
        }
        sb.append(']');
        return sb.toString();
    }

    public Iterator<ASN1Encodable> iterator()
    {
        return new Arrays.Iterator<ASN1Encodable>(toArray());
    }

    private static byte[] getDEREncoded(ASN1Encodable obj)
    {
        try
        {
            return obj.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("cannot encode object added to SET");
        }
    }

    /**
     * return true if a <= b (arrays are assumed padded with zeros).
     */
    private static boolean lessThanOrEqual(byte[] a, byte[] b)
    {
//        assert a.length >= 2 && b.length >= 2;

        /*
         * NOTE: Set elements in DER encodings are ordered first according to their tags (class and
         * number); the CONSTRUCTED bit is not part of the tag.
         * 
         * For SET-OF, this is unimportant. All elements have the same tag and DER requires them to
         * either all be in constructed form or all in primitive form, according to that tag. The
         * elements are effectively ordered according to their content octets.
         * 
         * For SET, the elements will have distinct tags, and each will be in constructed or
         * primitive form accordingly. Failing to ignore the CONSTRUCTED bit could therefore lead to
         * ordering inversions.
         */
        int a0 = a[0] & ~BERTags.CONSTRUCTED;
        int b0 = b[0] & ~BERTags.CONSTRUCTED;
        if (a0 != b0)
        {
            return a0 < b0;
        }

        int last = Math.min(a.length, b.length) - 1;
        for (int i = 1; i < last; ++i)
        {
            if (a[i] != b[i])
            {
                return (a[i] & 0xFF) < (b[i] & 0xFF);
            }
        }
        return (a[last] & 0xFF) <= (b[last] & 0xFF);
    }

    private static void sort(ASN1Encodable[] t)
    {
        int count = t.length;
        if (count < 2)
        {
            return;
        }

        ASN1Encodable eh = t[0], ei = t[1];
        byte[] bh = getDEREncoded(eh), bi = getDEREncoded(ei);;

        if (lessThanOrEqual(bi, bh))
        {
            ASN1Encodable et = ei; ei = eh; eh = et;
            byte[] bt = bi; bi = bh; bh = bt;
        }

        for (int i = 2; i < count; ++i)
        {
            ASN1Encodable e2 = t[i];
            byte[] b2 = getDEREncoded(e2);

            if (lessThanOrEqual(bi, b2))
            {
                t[i - 2] = eh;
                eh = ei; bh = bi;
                ei = e2; bi = b2;
                continue;
            }

            if (lessThanOrEqual(bh, b2))
            {
                t[i - 2] = eh;
                eh = e2; bh = b2;
                continue;
            }

            int j = i - 1;
            while (--j > 0)
            {
                ASN1Encodable e1 = t[j - 1];
                byte[] b1 = getDEREncoded(e1);

                if (lessThanOrEqual(b1, b2))
                {
                    break;
                }

                t[j] = e1;
            }

            t[j] = e2;
        }

        t[count - 2] = eh;
        t[count - 1] = ei;
    }
}
