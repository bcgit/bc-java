package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A parser for indefinite-length ASN.1 Private objects.
 * 
 * @deprecated Test for {@link BERTaggedObjectParser} with
 *             {@link ASN1TaggedObjectParser#getTagClass() tag class} of
 *             {@link BERTags#PRIVATE}.
 */
public class BERPrivateParser
    extends BERTaggedObjectParser
    implements ASN1PrivateParser
{
    BERPrivateParser(int tagNo, boolean constructed, ASN1StreamParser parser)
    {
        super(BERTags.PRIVATE, tagNo, constructed, parser);
    }

    /**
     * Return the object contained in this private object,
     * @return the contained object.
     * @throws IOException if the underlying stream cannot be read, or does not contain an ASN.1 encoding.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }
}
