package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public abstract class ASN1TaggedObject
    extends ASN1Primitive
    implements ASN1TaggedObjectParser
{
    private static final int DECLARED_EXPLICIT = 1;
    private static final int DECLARED_IMPLICIT = 2;
    // TODO It will probably be better to track parsing constructed vs primitive instead
    private static final int PARSED_EXPLICIT = 3;
    private static final int PARSED_IMPLICIT = 4;

    public static ASN1TaggedObject getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1TaggedObject) 
        {
            return (ASN1TaggedObject)obj;
        }
//      else if (obj instanceof ASN1TaggedObjectParser)
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1TaggedObject)
            {
                return (ASN1TaggedObject)primitive;
            }
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return checkedCast(fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct tagged object from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1TaggedObject getInstance(Object obj, int tagClass)
    {
        if (obj == null)
        {
            throw new NullPointerException("'obj' cannot be null");
        }

        ASN1TaggedObject taggedObject = getInstance(obj);
        if (tagClass != taggedObject.getTagClass())
        {
            throw new IllegalArgumentException("unexpected tag in getInstance: " + ASN1Util.getTagText(taggedObject));
        }

        return taggedObject;
    }

    public static ASN1TaggedObject getInstance(Object obj, int tagClass, int tagNo)
    {
        if (obj == null)
        {
            throw new NullPointerException("'obj' cannot be null");
        }

        ASN1TaggedObject taggedObject = getInstance(obj);
        if (!taggedObject.hasTag(tagClass, tagNo))
        {
            throw new IllegalArgumentException("unexpected tag in getInstance: " + ASN1Util.getTagText(taggedObject));
        }

        return taggedObject;
    }

    public static ASN1TaggedObject getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        if (BERTags.CONTEXT_SPECIFIC != taggedObject.getTagClass())
        {
            throw new IllegalStateException("this method only valid for CONTEXT_SPECIFIC tags");
        }

        if (declaredExplicit)
        {
            return taggedObject.getExplicitBaseTagged();
        }

        throw new IllegalArgumentException("this method not valid for implicitly tagged tagged objects");
    }

    final int           explicitness;
    final int           tagClass;
    final int           tagNo;
    final ASN1Encodable obj;

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
        this(explicit ? DECLARED_EXPLICIT : DECLARED_IMPLICIT, tagClass, tagNo, obj);
    }

    ASN1TaggedObject(int explicitness, int tagClass, int tagNo, ASN1Encodable obj)
    {
        if (null == obj)
        {
            throw new NullPointerException("'obj' cannot be null");
        }
        if (tagClass == BERTags.UNIVERSAL || (tagClass & BERTags.PRIVATE) != tagClass)
        {
            throw new IllegalArgumentException("invalid tag class: " + tagClass);
        }

        this.explicitness = (obj instanceof ASN1Choice) ? DECLARED_EXPLICIT : explicitness;
        this.tagClass = tagClass;
        this.tagNo = tagNo;
        this.obj = obj;
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1TaggedObject))
        {
            return false;
        }

        ASN1TaggedObject that = (ASN1TaggedObject)other;

        if (this.tagNo != that.tagNo ||
            this.tagClass != that.tagClass)
        {
            return false;
        }

        if (this.explicitness != that.explicitness)
        {
            /*
             * TODO This seems incorrect for some cases of implicit tags e.g. if one is a
             * declared-implicit SET and the other a parsed object.
             */
            if (this.isExplicit() != that.isExplicit())
            {
                return false;
            }
        }

        ASN1Primitive p1 = this.obj.toASN1Primitive();
        ASN1Primitive p2 = that.obj.toASN1Primitive();

        if (p1 == p2)
        {
            return true;
        }

        if (!this.isExplicit())
        {
            try
            {
                byte[] d1 = this.getEncoded();
                byte[] d2 = that.getEncoded();
                
                return Arrays.areEqual(d1, d2);
            }
            catch (IOException e)
            {
                return false;
            }
        }

        return p1.asn1Equals(p2);
    }

    public int hashCode()
    {
        return (tagClass * 7919) ^ tagNo ^ (isExplicit() ? 0x0F : 0xF0) ^ obj.toASN1Primitive().hashCode();
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

    public boolean hasContextTag()
    {
        return this.tagClass == BERTags.CONTEXT_SPECIFIC;
    }

    public boolean hasContextTag(int tagNo)
    {
        return this.tagClass == BERTags.CONTEXT_SPECIFIC && this.tagNo == tagNo;
    }

    public boolean hasTag(int tagClass, int tagNo)
    {
        return this.tagClass == tagClass && this.tagNo == tagNo;
    }

    public boolean hasTagClass(int tagClass)
    {
        return this.tagClass == tagClass;
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
        // TODO New methods like 'isKnownExplicit' etc. to distinguish uncertain cases?
        switch (explicitness)
        {
        case DECLARED_EXPLICIT:
        case PARSED_EXPLICIT:
            return true;
        default:
            return false;
        }
    }

    boolean isParsed()
    {
        switch (explicitness)
        {
        case PARSED_EXPLICIT:
        case PARSED_IMPLICIT:
            return true;
        default:
            return false;
        }
    }

    /**
     * Needed for open types, until we have better type-guided parsing support. Use sparingly for other
     * purposes, and prefer {@link #getExplicitBaseTagged()}, {@link #getImplicitBaseTagged(int, int)} or
     * {@link #getBaseUniversal(boolean, int)} where possible. Before using, check for matching tag
     * {@link #getTagClass() class} and {@link #getTagNo() number}.
     */
    public ASN1Object getBaseObject()
    {
        return obj instanceof ASN1Object ? (ASN1Object)obj : obj.toASN1Primitive();
    }

    /**
     * Needed for open types, until we have better type-guided parsing support. Use
     * sparingly for other purposes, and prefer {@link #getExplicitBaseTagged()} or
     * {@link #getBaseUniversal(boolean, int)} where possible. Before using, check
     * for matching tag {@link #getTagClass() class} and {@link #getTagNo() number}.
     */
    public ASN1Object getExplicitBaseObject()
    {
        if (!isExplicit())
        {
            throw new IllegalStateException("object implicit - explicit expected.");
        }

        return obj instanceof ASN1Object ? (ASN1Object)obj : obj.toASN1Primitive();
    }

    public ASN1TaggedObject getExplicitBaseTagged()
    {
        if (!isExplicit())
        {
            throw new IllegalStateException("object implicit - explicit expected.");
        }

        return checkedCast(obj.toASN1Primitive());
    }

    public ASN1TaggedObject getImplicitBaseTagged(int baseTagClass, int baseTagNo)
    {
        if (baseTagClass == BERTags.UNIVERSAL || (baseTagClass & BERTags.PRIVATE) != baseTagClass)
        {
            throw new IllegalArgumentException("invalid base tag class: " + baseTagClass);
        }

        switch (explicitness)
        {
        case DECLARED_EXPLICIT:
            throw new IllegalStateException("object explicit - implicit expected.");

        case DECLARED_IMPLICIT:
        {
            ASN1TaggedObject declared = checkedCast(obj.toASN1Primitive());
            return ASN1Util.checkTag(declared, baseTagClass, baseTagNo);
        }

        // Parsed; return a virtual tag (i.e. that couldn't have been present in the encoding)
        default:
            return replaceTag(baseTagClass, baseTagNo);
        }
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
    public ASN1Primitive getBaseUniversal(boolean declaredExplicit, int tagNo)
    {
        ASN1UniversalType universalType = ASN1UniversalTypes.get(tagNo);
        if (null == universalType)
        {
            throw new IllegalArgumentException("unsupported UNIVERSAL tag number: " + tagNo);
        }

        return getBaseUniversal(declaredExplicit, universalType);
    }

    ASN1Primitive getBaseUniversal(boolean declaredExplicit, ASN1UniversalType universalType)
    {
        if (declaredExplicit)
        {
            if (!isExplicit())
            {
                throw new IllegalStateException("object explicit - implicit expected.");
            }

            return universalType.checkedCast(obj.toASN1Primitive());
        }

        if (DECLARED_EXPLICIT == explicitness)
        {
            throw new IllegalStateException("object explicit - implicit expected.");
        }

        ASN1Primitive primitive = obj.toASN1Primitive();
        switch (explicitness)
        {
        case PARSED_EXPLICIT:
            return universalType.fromImplicitConstructed(rebuildConstructed(primitive));
        case PARSED_IMPLICIT:
        {
            if (primitive instanceof ASN1Sequence)
            {
                return universalType.fromImplicitConstructed((ASN1Sequence)primitive);
            }
            return universalType.fromImplicitPrimitive((DEROctetString)primitive);
        }
        default:
            return universalType.checkedCast(primitive);
        }
    }

    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException
    {
        ASN1Primitive primitive = getBaseUniversal(declaredExplicit, baseTagNo);

        switch (baseTagNo)
        {
        case BERTags.BIT_STRING:
            return ((ASN1BitString)primitive).parser();
        case BERTags.OCTET_STRING:
            return ((ASN1OctetString)primitive).parser();
        case BERTags.SEQUENCE:
            return ((ASN1Sequence)primitive).parser();
        case BERTags.SET:
            return ((ASN1Set)primitive).parser();
        }

        return primitive;
    }

    public ASN1Encodable parseExplicitBaseObject() throws IOException
    {
        return getExplicitBaseObject();
    }

    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException
    {
        return getExplicitBaseTagged();
    }

    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException
    {
        return getImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public final ASN1Primitive getLoadedObject()
    {
        return this;
    }

    abstract ASN1Sequence rebuildConstructed(ASN1Primitive primitive);

    abstract ASN1TaggedObject replaceTag(int tagClass, int tagNo);

    ASN1Primitive toDERObject()
    {
        return new DERTaggedObject(explicitness, tagClass, tagNo, obj);
    }

    ASN1Primitive toDLObject()
    {
        return new DLTaggedObject(explicitness, tagClass, tagNo, obj);
    }

    public String toString()
    {
        return ASN1Util.getTagText(tagClass, tagNo) + obj;
    }

    static ASN1Primitive createConstructedDL(int tagClass, int tagNo, ASN1EncodableVector contentsElements)
    {
        boolean maybeExplicit = (contentsElements.size() == 1);

        return maybeExplicit
            ?   new DLTaggedObject(PARSED_EXPLICIT, tagClass, tagNo, contentsElements.get(0))
            :   new DLTaggedObject(PARSED_IMPLICIT, tagClass, tagNo, DLFactory.createSequence(contentsElements));
    }

    static ASN1Primitive createConstructedIL(int tagClass, int tagNo, ASN1EncodableVector contentsElements)
    {
        boolean maybeExplicit = (contentsElements.size() == 1);

        return maybeExplicit
            ?   new BERTaggedObject(PARSED_EXPLICIT, tagClass, tagNo, contentsElements.get(0))
            :   new BERTaggedObject(PARSED_IMPLICIT, tagClass, tagNo, BERFactory.createSequence(contentsElements));
    }

    static ASN1Primitive createPrimitive(int tagClass, int tagNo, byte[] contentsOctets)
    {
        // Note: !CONSTRUCTED => IMPLICIT
        return new DLTaggedObject(PARSED_IMPLICIT, tagClass, tagNo, new DEROctetString(contentsOctets));
    }

    private static ASN1TaggedObject checkedCast(ASN1Primitive primitive)
    {
        if (primitive instanceof ASN1TaggedObject)
        {
            return (ASN1TaggedObject)primitive;
        }

        throw new IllegalStateException("unexpected object: " + primitive.getClass().getName());
    }
}
