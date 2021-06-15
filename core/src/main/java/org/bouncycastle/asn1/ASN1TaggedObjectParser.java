package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Interface for the parsing of a generic tagged ASN.1 object.
 */
public interface ASN1TaggedObjectParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Return the tag class associated with this object.
     *
     * @return the tag class.
     */
    int getTagClass();

    /**
     * Return the tag number associated with this object.
     *
     * @return the tag number.
     */
    int getTagNo();

    /**
     * Return a parser for the actual object tagged.
     *
     * @param tag the primitive tag value for the object tagged originally.
     * @param isExplicit true if the tagging was done explicitly.
     * @return a parser for the tagged object.
     * @throws IOException if a parser cannot be constructed.
     */
    ASN1Encodable getObjectParser(int tag, boolean isExplicit)
        throws IOException;
}
