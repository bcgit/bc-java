package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 * <p>
 * <hr>
 * <h2>X.690</h2>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.14 Encoding of a tagged value </h4>
 * <b>8.14.1</b> The encoding of a tagged value shall be derived from
 * the complete encoding of the corresponding data value of the type
 * appearing in the "TaggedType" notation (called the base encoding)
 * as specified in 8.14.2 and 8.14.3. 
 * <p>
 * <b>8.14.2</b> If implicit tagging (see ITU-T Rec. X.680 | ISO/IEC 8824-1, 30.6)
 * was not used in the definition of the type, the encoding shall be constructed
 * and the contents octets shall be the complete base encoding.
 * <p>
 * <b>8.14.3</b> If implicit tagging was used in the definition of the type, then:
 * <ol type="a">
 * <li>the encoding shall be constructed if the base encoding
 * is constructed, and shall be primitive otherwise; and
 * <li>the contents octets shall be the same as the contents
 * octets of the base encoding.
 * </ol>
 */
public abstract class ASN1TaggedObject
    extends ASN1Primitive
    implements ASN1TaggedObjectParser
{
    int             tagNo;
    boolean         empty = false;
    boolean         explicit = true;
    ASN1Encodable obj = null;

    static public ASN1TaggedObject getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        if (explicit)
        {
            return (ASN1TaggedObject)obj.getObject();
        }

        throw new IllegalArgumentException("implicitly tagged tagged object");
    }

    /**
     * Return an ASN1Sequence from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1TaggedObject} object
     * <li> byte[] of DER data containing an ASN1TaggedObject
     * </ul>
     *
     * @param obj the object to be converted.
     * @return converted object.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    static public ASN1TaggedObject getInstance(
        Object obj) 
    {
        if (obj == null || obj instanceof ASN1TaggedObject) 
        {
                return (ASN1TaggedObject)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return ASN1TaggedObject.getInstance(fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct tagged object from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Create a tagged object with the style given by the value of explicit.
     * <p>
     * If the object implements ASN1Choice the tag style will always be changed
     * to explicit in accordance with the ASN.1 encoding rules.
     * </p>
     * @param explicit true if the object is explicitly tagged.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public ASN1TaggedObject(
        boolean         explicit,
        int             tagNo,
        ASN1Encodable   obj)
    {
        if (obj instanceof ASN1Choice)
        {
            this.explicit = true;
        }
        else
        {
            this.explicit = explicit;
        }
        
        this.tagNo = tagNo;

        if (this.explicit)
        {
            this.obj = obj;
        }
        else
        {
            ASN1Primitive prim = obj.toASN1Primitive();

            if (prim instanceof ASN1Set)
            {
                ASN1Set s = null;
            }

            this.obj = obj;
        }
    }
    
    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1TaggedObject))
        {
            return false;
        }
        
        ASN1TaggedObject other = (ASN1TaggedObject)o;
        
        if (tagNo != other.tagNo || empty != other.empty || explicit != other.explicit)
        {
            return false;
        }
        
        if(obj == null)
        {
            if (other.obj != null)
            {
                return false;
            }
        }
        else
        {
            if (!(obj.toASN1Primitive().equals(other.obj.toASN1Primitive())))
            {
                return false;
            }
        }
        
        return true;
    }
    
    public int hashCode()
    {
        int code = tagNo;

        // TODO: actually this is wrong - the problem is that a re-encoded
        // object may end up with a different hashCode due to implicit
        // tagging. As implicit tagging is ambiguous if a sequence is involved
        // it seems the only correct method for both equals and hashCode is to
        // compare the encodings...
        if (obj != null)
        {
            code ^= obj.hashCode();
        }

        return code;
    }

    public int getTagNo()
    {
        return tagNo;
    }

    /**
     * Return whether or not the object may be explicitly tagged. 
     * <p>
     * Note: if the object has been read from an input stream, the only
     * time you can be sure if isExplicit is returning the true state of
     * affairs is if it returns false. An implicitly tagged object may appear
     * to be explicitly tagged, so you need to understand the context under
     * which the reading was done as well, see getObject below.
     */
    public boolean isExplicit()
    {
        return explicit;
    }

    public boolean isEmpty()
    {
        return empty;
    }

    /**
     * Return whatever was following the tag.
     * <p>
     * Note: tagged objects are generally context dependent if you're
     * trying to extract a tagged object you should be going via the
     * appropriate getInstance method.
     */
    public ASN1Primitive getObject()
    {
        if (obj != null)
        {
            return obj.toASN1Primitive();
        }

        return null;
    }

    /**
     * Return the object held in this tagged object as a parser assuming it has
     * the type of the passed in tag. If the object doesn't have a parser
     * associated with it, the base object is returned.
     */
    public ASN1Encodable getObjectParser(
        int     tag,
        boolean isExplicit)
    {
        switch (tag)
        {
        case BERTags.SET:
            return ASN1Set.getInstance(this, isExplicit).parser();
        case BERTags.SEQUENCE:
            return ASN1Sequence.getInstance(this, isExplicit).parser();
        case BERTags.OCTET_STRING:
            return ASN1OctetString.getInstance(this, isExplicit).parser();
        }

        if (isExplicit)
        {
            return getObject();
        }

        throw new RuntimeException("implicit tagging not implemented for tag: " + tag);
    }

    public ASN1Primitive getLoadedObject()
    {
        return this.toASN1Primitive();
    }

    ASN1Primitive toDERObject()
    {
        return new DERTaggedObject(explicit, tagNo, obj);
    }

    ASN1Primitive toDLObject()
    {
        return new DLTaggedObject(explicit, tagNo, obj);
    }

    abstract void encode(ASN1OutputStream out)
        throws IOException;

    public String toString()
    {
        return "[" + tagNo + "]" + obj;
    }
}
