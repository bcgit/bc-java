package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A DER encoding version of an application specific object.
 * 
 * @deprecated Will be removed. See comments for
 *             {@link ASN1ApplicationSpecific}.
 */
public class DERApplicationSpecific 
    extends ASN1ApplicationSpecific
{
    /**
     * Create an application specific object from the passed in data. This will assume
     * the data does not represent a constructed object.
     *
     * @param tagNo the tag number for this object.
     * @param contentsOctets the encoding of the object's body.
     */
    public DERApplicationSpecific(int tagNo, byte[] contentsOctets)
    {
        super(new DERTaggedObject(false, BERTags.APPLICATION, tagNo, new DEROctetString(contentsOctets)));
    }

    /**
     * Create an application specific object with a tagging of explicit/constructed.
     *
     * @param tag the tag number for this object.
     * @param baseEncodable the object to be contained.
     */
    public DERApplicationSpecific(int tag, ASN1Encodable baseEncodable) throws IOException
    {
        this(true, tag, baseEncodable);
    }

    /**
     * Create an application specific object with the tagging style given by the value of explicit.
     *
     * @param explicit true if the object is explicitly tagged.
     * @param tagNo the tag number for this object.
     * @param baseEncodable the object to be contained.
     */
    public DERApplicationSpecific(boolean explicit, int tagNo, ASN1Encodable baseEncodable) throws IOException
    {
        super(new DERTaggedObject(explicit, BERTags.APPLICATION, tagNo, baseEncodable));
    }

    /**
     * Create an application specific object which is marked as constructed
     *
     * @param tagNo the tag number for this object.
     * @param contentsElements   the objects making up the application specific object.
     */
    public DERApplicationSpecific(int tagNo, ASN1EncodableVector contentsElements)
    {
        super(new DERTaggedObject(false, BERTags.APPLICATION, tagNo, DERFactory.createSequence(contentsElements)));
    }

    DERApplicationSpecific(ASN1TaggedObject taggedObject)
    {
        super(taggedObject);
    }

    ASN1Primitive toDERObject()
    {
        return this;
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}
