package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A parser for indefinite-length ASN.1 ApplicationSpecific objects.
 * 
 * @deprecated Test for {@link ASN1TaggedObjectParser} with
 *             {@link ASN1TaggedObjectParser#getTagClass() tag class} of
 *             {@link BERTags#APPLICATION} instead.
 */
public class BERApplicationSpecificParser
    extends BERTaggedObjectParser
    implements ASN1ApplicationSpecificParser
{
    BERApplicationSpecificParser(int tagNo, ASN1StreamParser parser)
    {
        super(BERTags.APPLICATION, tagNo, parser);
    }

    /**
     * Return the object contained in this application specific object,
     * @return the contained object.
     * @throws IOException if the underlying stream cannot be read, or does not contain an ASN.1 encoding.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        // NOTE: No way to say you're looking for an implicitly-tagged object via ASN1ApplicationSpecificParser
        return parseExplicitBaseObject();
    }
}
