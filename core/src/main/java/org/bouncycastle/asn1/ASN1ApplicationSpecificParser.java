package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Interface to parse ASN.1 ApplicationSpecific objects.
 * 
 * @deprecated Test for {@link ASN1TaggedObjectParser} with {@link ASN1TaggedObjectParser#getTagClass() tag
 *             class} of {@link BERTags#APPLICATION} instead.
 */
public interface ASN1ApplicationSpecificParser
    extends ASN1TaggedObjectParser
{
    /**
     * Read the next object in the parser.
     *
     * @return an ASN1Encodable
     * @throws IOException on a parsing or decoding error.
     */
    ASN1Encodable readObject()
        throws IOException;
}
