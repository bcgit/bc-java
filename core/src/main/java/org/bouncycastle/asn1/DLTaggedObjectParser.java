package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser for definite-length tagged objects.
 */
class DLTaggedObjectParser
    extends BERTaggedObjectParser
{
    private boolean _constructed;

    DLTaggedObjectParser(int tagClass, int tagNo, boolean constructed, ASN1StreamParser parser)
    {
        super(tagClass, tagNo, parser);

        _constructed = constructed;
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
        return _constructed;
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
        return _parser.loadTaggedDL(_tagClass, _tagNo, _constructed);
    }

    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException
    {
        if (declaredExplicit)
        {
            if (!_constructed)
            {
                throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
            }

            return _parser.parseObject(baseTagNo);
        }

        return _constructed
            ?  _parser.parseImplicitConstructedDL(baseTagNo)
            :  _parser.parseImplicitPrimitive(baseTagNo);
    }

    public ASN1Encodable parseExplicitBaseObject() throws IOException
    {
        if (!_constructed)
        {
            throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
        }

        return _parser.readObject();
    }

    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException
    {
        if (!_constructed)
        {
            throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
        }

        return _parser.parseTaggedObject();
    }

    public ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException
    {
        // TODO[asn1] Special handling can be removed once ASN1ApplicationSpecific types removed.
        if (BERTags.APPLICATION == baseTagClass)
        {
            // This cast is ensuring the current user-expected return type.
            return (DLApplicationSpecific)_parser.loadTaggedDL(baseTagClass, baseTagNo, _constructed);
        }

        return new DLTaggedObjectParser(baseTagClass, baseTagNo, _constructed, _parser);
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