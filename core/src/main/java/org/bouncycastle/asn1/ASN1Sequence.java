package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.bouncycastle.util.Arrays;

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
 * <p>
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 * </p>
 */
public abstract class ASN1Sequence
    extends ASN1Primitive
    implements org.bouncycastle.util.Iterable<ASN1Encodable>
{
    // NOTE: Only non-final to support LazyEncodedSequence
    ASN1Encodable[] elements;

    /**
     * Return an ASN1Sequence from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Sequence instance, or null.
     */
    public static ASN1Sequence getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Sequence)
        {
            return (ASN1Sequence)obj;
        }
        else if (obj instanceof ASN1SequenceParser)
        {
            return ASN1Sequence.getInstance(((ASN1SequenceParser)obj).toASN1Primitive());
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return ASN1Sequence.getInstance(fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct sequence from byte[]: " + e.getMessage());
            }
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

            if (primitive instanceof ASN1Sequence)
            {
                return (ASN1Sequence)primitive;
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an ASN1 SEQUENCE from a tagged object. There is a special
     * case here, if an object appears to have been explicitly tagged on 
     * reading but we were expecting it to be implicitly tagged in the 
     * normal course of events it indicates that we lost the surrounding
     * sequence - so we need to add it back (this will happen if the tagged
     * object is a sequence that contains other sequences). If you are
     * dealing with implicitly tagged sequences you really <b>should</b>
     * be using this method.
     *
     * @param taggedObject the tagged object.
     * @param explicit true if the object is meant to be explicitly tagged,
     *          false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *          be converted.
     * @return an ASN1Sequence instance.
     */
    public static ASN1Sequence getInstance(
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
         * constructed object which appears to be explicitly tagged when it should be implicit means
         * we have to add the surrounding sequence.
         */
        if (taggedObject.isExplicit())
        {
            if (taggedObject instanceof BERTaggedObject)
            {
                return new BERSequence(o);
            }

            return new DLSequence(o);
        }

        if (o instanceof ASN1Sequence)
        {
            ASN1Sequence s = (ASN1Sequence)o;

            if (taggedObject instanceof BERTaggedObject)
            {
                return s;
            }

            return (ASN1Sequence)s.toDLObject();
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + taggedObject.getClass().getName());
    }

    /**
     * Create an empty SEQUENCE
     */
    protected ASN1Sequence()
    {
        this.elements = ASN1EncodableVector.EMPTY_ELEMENTS;
    }

    /**
     * Create a SEQUENCE containing one object.
     * @param element the object to be put in the SEQUENCE.
     */
    protected ASN1Sequence(ASN1Encodable element)
    {
        if (null == element)
        {
            throw new NullPointerException("'element' cannot be null");
        }

        this.elements = new ASN1Encodable[]{ element };
    }

    /**
     * Create a SEQUENCE containing a vector of objects.
     * @param elementVector the vector of objects to be put in the SEQUENCE.
     */
    protected ASN1Sequence(ASN1EncodableVector elementVector)
    {
        if (null == elementVector)
        {
            throw new NullPointerException("'elementVector' cannot be null");
        }

        this.elements = elementVector.takeElements();
    }

    /**
     * Create a SEQUENCE containing an array of objects.
     * @param elements the array of objects to be put in the SEQUENCE.
     */
    protected ASN1Sequence(ASN1Encodable[] elements)
    {
        if (Arrays.isNullOrContainsNull(elements))
        {
            throw new NullPointerException("'elements' cannot be null, or contain null");
        }

        this.elements = ASN1EncodableVector.cloneElements(elements);
    }

    ASN1Sequence(ASN1Encodable[] elements, boolean clone)
    {
        this.elements = clone ? ASN1EncodableVector.cloneElements(elements) : elements;
    }

    public ASN1Encodable[] toArray()
    {
        return ASN1EncodableVector.cloneElements(elements);
    }

    ASN1Encodable[] toArrayInternal()
    {
        return elements;
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

    public ASN1SequenceParser parser()
    {
        // NOTE: Call size() here to 'force' a LazyEncodedSequence
        final int count = size();

        return new ASN1SequenceParser()
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
                return ASN1Sequence.this;
            }

            public ASN1Primitive toASN1Primitive()
            {
                return ASN1Sequence.this;
            }
        };
    }

    /**
     * Return the object at the sequence position indicated by index.
     *
     * @param index the sequence number (starting at zero) of the object
     * @return the object at the sequence position indicated by index.
     */
    public ASN1Encodable getObjectAt(int index)
    {
        return elements[index];
    }

    /**
     * Return the number of objects in this sequence.
     *
     * @return the number of objects in this sequence.
     */
    public int size()
    {
        return elements.length;
    }

    public int hashCode()
    {
//        return Arrays.hashCode(elements);
        int i = elements.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= elements[i].toASN1Primitive().hashCode();
        }

        return hc;
    }

    boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1Sequence))
        {
            return false;
        }

        ASN1Sequence that = (ASN1Sequence)other;

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

    /**
     * Change current SEQUENCE object to be encoded as {@link DERSequence}.
     * This is part of Distinguished Encoding Rules form serialization.
     */
    ASN1Primitive toDERObject()
    {
        return new DERSequence(elements, false);
    }

    /**
     * Change current SEQUENCE object to be encoded as {@link DLSequence}.
     * This is part of Direct Length form serialization.
     */
    ASN1Primitive toDLObject()
    {
        return new DLSequence(elements, false);
    }

    boolean isConstructed()
    {
        return true;
    }

    abstract void encode(ASN1OutputStream out, boolean withTag) throws IOException;

    public String toString() 
    {
        // NOTE: Call size() here to 'force' a LazyEncodedSequence
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
        return new Arrays.Iterator<ASN1Encodable>(elements);
    }
}
