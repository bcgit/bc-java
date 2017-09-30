package com.github.gv2011.asn1;


/**
 * Parser for indefinite-length tagged objects.
 */
public class BERTaggedObjectParser
    implements ASN1TaggedObjectParser
{
    private final boolean _constructed;
    private final int _tagNumber;
    private final ASN1StreamParser _parser;

    BERTaggedObjectParser(
        final boolean             constructed,
        final int                 tagNumber,
        final ASN1StreamParser    parser)
    {
        _constructed = constructed;
        _tagNumber = tagNumber;
        _parser = parser;
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
     * Return the tag number associated with this object.
     *
     * @return the tag number.
     */
    @Override
    public int getTagNo()
    {
        return _tagNumber;
    }

    /**
     * Return an object parser for the contents of this tagged object.
     *
     * @param tag the actual tag number of the object (needed if implicit).
     * @param isExplicit true if the contained object was explicitly tagged, false if implicit.
     * @return an ASN.1 encodable object parser.
     * @throws IOException if there is an issue building the object parser from the stream.
     */
    @Override
    public ASN1Encodable getObjectParser(
        final int     tag,
        final boolean isExplicit)
    {
        if (isExplicit)
        {
            if (!_constructed)
            {
                throw new ASN1Exception("Explicit tags must be constructed (see X.690 8.14.2)");
            }
            return _parser.readObject();
        }

        return _parser.readImplicit(_constructed, tag);
    }

    /**
     * Return an in-memory, encodable, representation of the tagged object.
     *
     * @return an ASN1TaggedObject.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject()
    {
        return _parser.readTaggedObject(_constructed, _tagNumber);
    }

    /**
     * Return an ASN1TaggedObject representing this parser and its contents.
     *
     * @return an ASN1TaggedObject
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
     }
}