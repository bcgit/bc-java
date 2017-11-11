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
 * ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
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
        final ASN1TaggedObject    obj,
        final boolean             explicit)
    {
        if (explicit)
        {
            return (ASN1TaggedObject)obj.getObject();
        }

        throw new IllegalArgumentException("implicitly tagged tagged object");
    }

    static public ASN1TaggedObject getInstance(
        final Object obj)
    {
        if (obj == null || obj instanceof ASN1TaggedObject)
        {
                return (ASN1TaggedObject)obj;
        }
        else if (obj instanceof Bytes)
        {
            return ASN1TaggedObject.getInstance(fromBytes((Bytes)obj));
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
        final boolean         explicit,
        final int             tagNo,
        final ASN1Encodable   obj)
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

          //TODO: WTF?
          final ASN1Primitive prim = obj.toASN1Primitive();
          if (prim instanceof ASN1Set)
          {
              @SuppressWarnings("unused")
              final ASN1Set s = null;
          }

          this.obj = obj;
        }
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1TaggedObject))
        {
            return false;
        }

        final ASN1TaggedObject other = (ASN1TaggedObject)o;

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

    @Override
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

    @Override
    public int getTagNo()
    {
        return tagNo;
    }

    /**
     * return whether or not the object may be explicitly tagged.
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
     * return whatever was following the tag.
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
    @Override
    public ASN1Encodable getObjectParser(
        final int     tag,
        final boolean isExplicit)
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

        throw new ASN1Exception("implicit tagging not implemented for tag: " + tag);
    }

    @Override
    public ASN1Primitive getLoadedObject()
    {
        return toASN1Primitive();
    }

    @Override
    ASN1Primitive toDERObject()
    {
        return new DERTaggedObject(explicit, tagNo, obj);
    }

    @Override
    ASN1Primitive toDLObject()
    {
        return new DLTaggedObject(explicit, tagNo, obj);
    }

    @Override
    abstract void encode(ASN1OutputStream out);

    @Override
    public String toString()
    {
        return "[" + tagNo + "]" + obj;
    }
}
