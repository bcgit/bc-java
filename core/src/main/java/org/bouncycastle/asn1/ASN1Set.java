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
    private static final ASN1Encodable[] EMPTY_ELEMENTS = new ASN1Encodable[0];

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
     * @param obj the tagged object.
     * @param explicit true if the object is meant to be explicitly tagged
     *          false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *          be converted.
     * @return an ASN1Set instance.
     */
    public static ASN1Set getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
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
            ASN1Primitive o = obj.getObject();

            //
            // constructed object which appears to be explicitly tagged
            // and it's really implicit means we have to add the
            // surrounding set.
            //
            if (obj.isExplicit())
            {
                if (obj instanceof BERTaggedObject)
                {
                    return new BERSet(o);
                }
                else
                {
                    return new DLSet(o);
                }
            }
            else
            {
                if (o instanceof ASN1Set)
                {
                    return (ASN1Set)o;
                }

                //
                // in this case the parser returns a sequence, convert it
                // into a set.
                //
                if (o instanceof ASN1Sequence)
                {
                    ASN1Sequence s = (ASN1Sequence)o;

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
        this.elements = EMPTY_ELEMENTS;
        this.isSorted = true;
    }

    /**
     * Create a SET containing one object
     * @param obj object to be added to the SET.
     */
    protected ASN1Set(ASN1Encodable obj)
    {
        this.elements = new ASN1Encodable[]{ obj };
        this.isSorted = true;
    }

    /**
     * Create a SET containing a vector of objects.
     * @param v a vector of objects to make up the SET.
     * @param doSort true if should be sorted DER style, false otherwise.
     */
    protected ASN1Set(ASN1EncodableVector v, boolean doSort)
    {
        int count = v.size();

        ASN1Encodable[] tmp;
        switch (count)
        {
        case 0:
            tmp = EMPTY_ELEMENTS;
            break;
        case 1:
            tmp = new ASN1Encodable[]{ v.get(0) };
            break;
        default:
        {
            tmp = new ASN1Encodable[count];
            for (int i = 0; i < count; ++i)
            {
                tmp[i] = v.get(i);
            }
            if (doSort)
            {
                sort(tmp);
            }
            break;
        }
        }

        this.elements = tmp;
        this.isSorted = doSort;
    }

    /**
     * Create a SET containing an array of objects.
     * @param array an array of objects to make up the SET.
     * @param doSort true if should be sorted DER style, false otherwise.
     */
    protected ASN1Set(ASN1Encodable[] array, boolean doSort)
    {
        int count = array.length;

        ASN1Encodable[] tmp;
        switch (count)
        {
        case 0:
            tmp = EMPTY_ELEMENTS;
            break;
        case 1:
            tmp = new ASN1Encodable[]{ array[0] };
            break;
        default:
        {
            tmp = array.clone();
            if (doSort)
            {
                sort(tmp);
            }
            break;
        }
        }

        this.elements = tmp;
        this.isSorted = doSort;
    }

    ASN1Set(boolean isSorted, ASN1Encodable[] elements)
    {
        this.elements = elements;
        this.isSorted = isSorted;
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
                if (pos >= elements.length)
                {
                    throw new NoSuchElementException("ASN1Set Enumeration");
                }
                return elements[pos++];
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
        return elements.length < 1 ? EMPTY_ELEMENTS : elements.clone();
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
        return Arrays.hashCode(elements);
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
            tmp = elements.clone();

            sort(tmp);
        }

        return new DERSet(isSorted, tmp);
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

        for (int i = 0; i < count; ++i)
        {
            ASN1Primitive p1 = this.elements[i].toASN1Primitive();
            ASN1Primitive p2 = that.elements[i].toASN1Primitive();

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

    abstract void encode(ASN1OutputStream out)
            throws IOException;

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
    private static boolean lessThanOrEqual(
         byte[] a,
         byte[] b)
    {
        int len = Math.min(a.length, b.length);
        for (int i = 0; i != len; ++i)
        {
            if (a[i] != b[i])
            {
                return (a[i] & 0xff) < (b[i] & 0xff);
            }
        }
        return len == a.length;
    }

    private static void sort(ASN1Encodable[] t)
    {
        int count = t.length;
        if (count < 2)
        {
            return;
        }

        ASN1Encodable ei = t[0];
        byte[] bi = getDEREncoded(ei);;

        for (int i = 1; i < count; ++i)
        {
            ASN1Encodable e2 = t[i];
            byte[] b2 = getDEREncoded(e2);

            if (lessThanOrEqual(bi, b2))
            {
                t[i - 1] = ei;
                ei = e2;
                bi = b2;
                continue;
            }

            int j = i;
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

        t[count - 1] = ei;
    }
}
