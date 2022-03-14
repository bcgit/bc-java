package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * A DER encoding version of an application specific object.
 * 
 * @deprecated Will be removed. See comments for
 *             {@link ASN1ApplicationSpecific}.
 */
public class DLApplicationSpecific
    extends ASN1ApplicationSpecific
{
    /**
     * Create an application specific object from the passed in data. This will assume
     * the data does not represent a constructed object.
     *
     * @param tagNo the tag number for this object.
     * @param contentsOctets the encoding of the object's body.
     */
    public DLApplicationSpecific(int tagNo, byte[] contentsOctets)
    {
        super(new DLTaggedObject(false, BERTags.APPLICATION, tagNo, new DEROctetString(Arrays.clone(contentsOctets))));
    }

    /**
     * Create an application specific object with a tagging of explicit/constructed.
     *
     * @param tagNo the tag number for this object.
     * @param baseEncodable the object to be contained.
     */
    public DLApplicationSpecific(int tagNo, ASN1Encodable baseEncodable) throws IOException
    {
        this(true, tagNo, baseEncodable);
    }

    /**
     * Create an application specific object with the tagging style given by the value of explicit.
     *
     * @param explicit true if the object is explicitly tagged.
     * @param tagNo the tag number for this object.
     * @param baseEncodable the object to be contained.
     */
    public DLApplicationSpecific(boolean explicit, int tagNo, ASN1Encodable baseEncodable) throws IOException
    {
        super(new DLTaggedObject(explicit, BERTags.APPLICATION, tagNo, baseEncodable));
    }

    /**
     * Create an application specific object which is marked as constructed
     *
     * @param tagNo the tag number for this object.
     * @param contentsElements   the objects making up the application specific object.
     */
    public DLApplicationSpecific(int tagNo, ASN1EncodableVector contentsElements)
    {
        super(new DLTaggedObject(false, BERTags.APPLICATION, tagNo, DLFactory.createSequence(contentsElements)));
    }

    DLApplicationSpecific(ASN1TaggedObject taggedObject)
    {
        super(taggedObject);
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}
