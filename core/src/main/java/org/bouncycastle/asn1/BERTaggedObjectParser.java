package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser for indefinite-length tagged objects.
 * 
 * @deprecated Will be made non-public. Test for and use only {@link ASN1TaggedObjectParser}.
 */
public class BERTaggedObjectParser
    implements ASN1TaggedObjectParser
{
    final int _tagClass;
    final int _tagNo;
    final ASN1StreamParser _parser;

    BERTaggedObjectParser(int tagClass, int tagNo, ASN1StreamParser parser)
    {
        _tagClass = tagClass;
        _tagNo = tagNo;
        _parser = parser;
    }

    public int getTagClass()
    {
        return _tagClass;
    }

    public int getTagNo()
    {
        return _tagNo;
    }

    public boolean hasContextTag(int tagNo)
    {
        return this._tagClass == BERTags.CONTEXT_SPECIFIC && this._tagNo == tagNo;
    }

    public boolean hasTag(int tagClass, int tagNo)
    {
        return this._tagClass == tagClass && this._tagNo == tagNo;
    }

    /**
     * Return true if this tagged object is marked as constructed.
     *
     * @return true if constructed, false otherwise.
     */
    public boolean isConstructed()
    {
        return true;
    }

    /**
     * Return an object parser for the contents of this tagged object.
     *
     * @param tag        the actual tag number of the object (needed if implicit).
     * @param isExplicit true if the contained object was explicitly tagged, false
     *                   if implicit.
     * @return an ASN.1 encodable object parser.
     * @throws IOException if there is an issue building the object parser from the
     *                     stream.
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

    /**
     * Return an in-memory, encodable, representation of the tagged object.
     *
     * @return an ASN1TaggedObject.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return _parser.loadTaggedIL(_tagClass, _tagNo);
    }

    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException
    {
        if (declaredExplicit)
        {
            return _parser.parseObject(baseTagNo);
        }

        return _parser.parseImplicitConstructedIL(baseTagNo);
    }

    public ASN1Encodable parseExplicitBaseObject() throws IOException
    {
        return _parser.readObject();
    }

    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException
    {
        return _parser.parseTaggedObject();
    }

    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException
    {
        // TODO[asn1] Special handling can be removed once ASN1ApplicationSpecificParser types removed.
        if (BERTags.APPLICATION == baseTagClass)
        {
            return new BERApplicationSpecificParser(baseTagNo, _parser);
        }

        return new BERTaggedObjectParser(baseTagClass, baseTagNo, _parser);
    }

    /**
     * Return an ASN1TaggedObject representing this parser and its contents.
     *
     * @return an ASN1TaggedObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException(e.getMessage());
        }
    }
}