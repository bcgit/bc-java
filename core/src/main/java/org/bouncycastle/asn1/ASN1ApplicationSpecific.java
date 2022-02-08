package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Base class for an ASN.1 ApplicationSpecific object
 *
 * @deprecated Will be removed. Change application code to handle as {@link ASN1TaggedObject} only, testing
 *             for the expected {@link ASN1TaggedObject#getTagClass() tag class} of
 *             {@link BERTags#APPLICATION} in relevant objects before using. If using a
 *             {@link ASN1StreamParser stream parser}, handle application-tagged objects using
 *             {@link ASN1TaggedObjectParser} in the usual way, again testing for a
 *             {@link ASN1TaggedObjectParser#getTagClass() tag class} of {@link BERTags#APPLICATION}.
 */
public abstract class ASN1ApplicationSpecific
    extends ASN1TaggedObject
    implements ASN1ApplicationSpecificParser
{
    /**
     * Return an ASN1ApplicationSpecific from the passed in object, which may be a byte array, or null.
     *
     * @param obj the object to be converted.
     * @return obj's representation as an ASN1ApplicationSpecific object.
     */
    public static ASN1ApplicationSpecific getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1ApplicationSpecific)
        {
            return (ASN1ApplicationSpecific)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Failed to construct object from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    final ASN1TaggedObject taggedObject;

    ASN1ApplicationSpecific(ASN1TaggedObject taggedObject)
    {
        super(taggedObject.explicitness, checkTagClass(taggedObject.tagClass), taggedObject.tagNo, taggedObject.obj);

        this.taggedObject = taggedObject;
    }

    /**
     * Return the tag number associated with this object,
     *
     * @return the application tag number.
     */
    public int getApplicationTag() 
    {
        return taggedObject.getTagNo();
    }

    /**
     * Return the contents of this object as a byte[]
     *
     * @return the encoded contents of the object.
     */
    public byte[] getContents()
    {
        return taggedObject.getContents();
    }

    /**
     * Return the enclosed object assuming explicit tagging.
     *
     * @return  the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getEnclosedObject() throws IOException
    {
        return taggedObject.getBaseObject().toASN1Primitive();
    }

    /**
     * Return the enclosed object assuming implicit tagging.
     *
     * @param tagNo the type tag that should be applied to the object's contents.
     * @return the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getObject(int tagNo) throws IOException
    {
        return taggedObject.getBaseUniversal(false, tagNo);
    }

    public ASN1Encodable getObjectParser(int tag, boolean isExplicit) throws IOException
    {
        throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
    }

    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException
    {
        return taggedObject.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    public ASN1Encodable parseExplicitBaseObject() throws IOException
    {
        return taggedObject.parseExplicitBaseObject();
    }

    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException
    {
        return taggedObject.parseExplicitBaseTagged();
    }

    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException
    {
        return taggedObject.parseImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public boolean hasApplicationTag(int tagNo)
    {
        return this.tagNo == tagNo;
    }

    public boolean hasContextTag(int tagNo)
    {
        return false;
    }

    /**
     * ASN1ApplicationSpecific uses an internal ASN1TaggedObject for the
     * implementation, and will soon be deprecated in favour of using
     * ASN1TaggedObject with a tag class of {@link BERTags#APPLICATION}. This method
     * lets you get the internal ASN1TaggedObject so that client code can begin the
     * migration.
     */
    public ASN1TaggedObject getTaggedObject()
    {
        return taggedObject;
    }

    /**
     * Return true if the object is marked as constructed, false otherwise.
     *
     * @return true if constructed, otherwise false.
     */
    public boolean isConstructed()
    {
        return taggedObject.isConstructed();
    }

    public ASN1Encodable readObject() throws IOException
    {
        // NOTE: No way to say you're looking for an implicitly-tagged object via ASN1ApplicationSpecificParser
        return parseExplicitBaseObject();
    }

    boolean encodeConstructed()
    {
        return taggedObject.encodeConstructed();
    }

    int encodedLength(boolean withTag) throws IOException
    {
        return taggedObject.encodedLength(withTag);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        taggedObject.encode(out, withTag);
    }

    String getASN1Encoding()
    {
        return taggedObject.getASN1Encoding();
    }

    ASN1Sequence rebuildConstructed(ASN1Primitive primitive)
    {
        return taggedObject.rebuildConstructed(primitive);
    }

    ASN1TaggedObject replaceTag(int tagClass, int tagNo)
    {
        return taggedObject.replaceTag(tagClass, tagNo);
    }

    ASN1Primitive toDERObject()
    {
        return new DERApplicationSpecific((ASN1TaggedObject)taggedObject.toDERObject());
    }

    ASN1Primitive toDLObject()
    {
        return new DLApplicationSpecific((ASN1TaggedObject)taggedObject.toDLObject());
    }

    private static int checkTagClass(int tagClass)
    {
        if (BERTags.APPLICATION != tagClass)
        {
            throw new IllegalArgumentException();
        }
        return tagClass;
    }
}
