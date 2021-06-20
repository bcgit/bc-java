package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public abstract class ASN1TaggedObject
    extends ASN1Primitive
    implements ASN1TaggedObjectParser
{
    final boolean       explicit;
    final int           tagClass;
    final int           tagNo;
    final ASN1Encodable obj;

    static public ASN1TaggedObject getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        if (explicit)
        {
            return getInstance(obj.getObject());
        }

        throw new IllegalArgumentException("implicitly tagged tagged object");
    }

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
    protected ASN1TaggedObject(boolean explicit, int tagNo, ASN1Encodable obj)
    {
        this(explicit, BERTags.CONTEXT_SPECIFIC, tagNo, obj);
    }

    protected ASN1TaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj)
    {
        if (null == obj)
        {
            throw new NullPointerException("'obj' cannot be null");
        }
        if (tagClass == BERTags.UNIVERSAL || (tagClass & BERTags.PRIVATE) != tagClass)
        {
            throw new IllegalArgumentException("invalid tag class: " + tagClass);
        }

        this.explicit = explicit || (obj instanceof ASN1Choice);
        this.tagClass = tagClass;
        this.tagNo = tagNo;
        this.obj = obj;
    }

    boolean asn1Equals(ASN1Primitive other)
    {
        if (other instanceof ASN1ApplicationSpecific)
        {
            return other.equals(this);
        }

        if (!(other instanceof ASN1TaggedObject))
        {
            return false;
        }

        ASN1TaggedObject that = (ASN1TaggedObject)other;

        if (this.tagNo != that.tagNo ||
            this.tagClass != that.tagClass ||
            this.explicit != that.explicit)
        {
            return false;
        }

        ASN1Primitive p1 = this.obj.toASN1Primitive();
        ASN1Primitive p2 = that.obj.toASN1Primitive();

        return p1 == p2 || p1.asn1Equals(p2);
    }

    public int hashCode()
    {
        return (tagClass * 7919) ^ tagNo ^ (explicit ? 0x0F : 0xF0) ^ obj.toASN1Primitive().hashCode();
    }

    public int getTagClass()
    {
        return tagClass;
    }

    /**
     * Return the tag number associated with this object.
     *
     * @return the tag number.
     */
    public int getTagNo()
    {
        return tagNo;
    }

    public boolean hasContextTag(int tagNo)
    {
        return this.tagClass == BERTags.CONTEXT_SPECIFIC && this.tagNo == tagNo;
    }

    public boolean hasTag(int tagClass, int tagNo)
    {
        return this.tagClass == tagClass && this.tagNo == tagNo;
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

    /**
     * Return the contents of this object as a byte[]
     *
     * @return the encoded contents of the object.
     */
    // TODO Need this public if/when ASN1ApplicationSpecific extends ASN1TaggedObject
    byte[] getContents()
    {
        try
        {
            byte[] baseEncoding = obj.toASN1Primitive().getEncoded(getASN1Encoding());
            if (isExplicit())
            {
                return baseEncoding;
            }

            ByteArrayInputStream input = new ByteArrayInputStream(baseEncoding);
            int tag = input.read();
            ASN1InputStream.readTagNumber(input, tag);
            int length = ASN1InputStream.readLength(input, input.available(), false);
            int remaining = input.available();

            // For indefinite form, account for end-of-contents octets
            int contentsLength = length < 0 ? remaining - 2 : remaining;
            if (contentsLength < 0)
            {
                throw new IllegalStateException();
            }

            byte[] contents = new byte[contentsLength];
            System.arraycopy(baseEncoding, baseEncoding.length - remaining, contents, 0, contentsLength);
            return contents;
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Return whatever was following the tag.
     * <p>
     * Note: tagged objects are generally context dependent. If you're trying to
     * extract a tagged object you should be going via the appropriate getInstance
     * method.
     * 
     * @deprecated Tagged objects now include the {@link #getTagClass() tag class}.
     *             This method will raise an exception if it is not
     *             {@link BERTags#CONTEXT_SPECIFIC}. Use
     *             {@link #getBaseUniversal(boolean, int)} only after confirming the
     *             expected tag class.
     */
    public ASN1Primitive getObject()
    {
        if (BERTags.CONTEXT_SPECIFIC != getTagClass())
        {
            throw new IllegalStateException("this method only valid for CONTEXT_SPECIFIC tags");
        }

        return obj.toASN1Primitive();
    }

    /**
     * Note: tagged objects are generally context dependent. Before trying to
     * extract a tagged object this way, make sure you have checked that both the
     * {@link #getTagClass() tag class} and {@link #getTagNo() tag number} match
     * what you are looking for.
     * 
     * @param declaredExplicit Whether the tagged type for this object was declared
     *                         EXPLICIT.
     * @param tagNo            The universal {@link BERTags tag number} of the
     *                         expected base object.
     */
    public ASN1Primitive getBaseUniversal(boolean declaredExplicit, int tagNo) throws IOException
    {
        if (tagNo < 1 || tagNo >= 0x1F)
        {
            throw new IOException("unsupported tag number");
        }

        if (declaredExplicit)
        {
            if (!isExplicit())
            {
                throw new IllegalArgumentException("object implicit - explicit expected.");
            }

            return obj.toASN1Primitive();
        }

        // TODO If this wasn't a parsed object AND it's marked explicit, this should be an error

        // Handle implicit objects generically by re-encoding with new tag

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ASN1OutputStream output = ASN1OutputStream.create(buf, getASN1Encoding());
        encode(output, true, BERTags.UNIVERSAL, tagNo);
        output.flushInternal();

        byte[] encoding = buf.toByteArray();

        return ASN1Primitive.fromByteArray(encoding);
    }

    /**
     * @deprecated See {@link ASN1TaggedObjectParser#getObjectParser(int, boolean)}.
     */
    public ASN1Encodable getObjectParser(int tag, boolean isExplicit) throws IOException
    {
        if (BERTags.CONTEXT_SPECIFIC != getTagClass())
        {
            throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
        }

        return parseBaseUniversal(isExplicit, tag);
    }

    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException
    {
        // TODO These method use getInstance that should only work for BERTags.CONTEXT_SPECIFIC
        switch (baseTagNo)
        {
        case BERTags.SET:
            return ASN1Set.getInstance(this, declaredExplicit).parser();
        case BERTags.SEQUENCE:
            return ASN1Sequence.getInstance(this, declaredExplicit).parser();
        case BERTags.OCTET_STRING:
            return ASN1OctetString.getInstance(this, declaredExplicit).parser();
        }

        return getBaseUniversal(declaredExplicit, baseTagNo);
    }

    public final ASN1Primitive getLoadedObject()
    {
        return this;
    }

    final void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        encode(out, withTag, getTagClass(), getTagNo());
    }

    abstract void encode(ASN1OutputStream out, boolean withTag, int tagClass, int tagNo) throws IOException;

    abstract String getASN1Encoding();

    ASN1Primitive toDERObject()
    {
        return new DERTaggedObject(explicit, tagClass, tagNo, obj);
    }

    ASN1Primitive toDLObject()
    {
        return new DLTaggedObject(explicit, tagClass, tagNo, obj);
    }

    public String toString()
    {
        return ASN1Util.getTagText(tagClass, tagNo) + obj;
    }

    static ASN1Primitive createConstructed(int tagClass, int tagNo, boolean isIL,
        ASN1EncodableVector contentsElements)
    {
        boolean maybeExplicit = (contentsElements.size() == 1);

        if (isIL)
        {
            switch (tagClass)
            {
            case BERTags.APPLICATION:
                return new BERApplicationSpecific(tagNo, contentsElements);
            default:
            {
                return maybeExplicit
                    ?   new BERTaggedObject(true, tagClass, tagNo, contentsElements.get(0))
                    :   new BERTaggedObject(false, tagClass, tagNo, BERFactory.createSequence(contentsElements));
            }
            }
        }

        switch (tagClass)
        {
        case BERTags.APPLICATION:
            return new DLApplicationSpecific(tagNo, contentsElements);
        default:
        {
            return maybeExplicit
                ?   new DLTaggedObject(true, tagClass, tagNo, contentsElements.get(0))
                :   new DLTaggedObject(false, tagClass, tagNo, DLFactory.createSequence(contentsElements));
        }
        }
    }

    static ASN1Primitive createPrimitive(int tagClass, int tagNo, byte[] contentsOctets)
    {
        // Note: !CONSTRUCTED => IMPLICIT
        switch (tagClass)
        {
        case BERTags.APPLICATION:
            return new DLApplicationSpecific(tagNo, contentsOctets);
        default:
            return new DLTaggedObject(false, tagClass, tagNo, new DEROctetString(contentsOctets));
        }
    }
}
