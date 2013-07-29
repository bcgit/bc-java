package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Interface for parse of a generic tagged ASN.1 object.
 */
public interface ASN1TaggedObjectParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Get tag code as an integer, it is never zero.
     */
    public int getTagNo();

    /**
     * Parse the given object.
     * @throws IOException for bad input stream.
     */
    public ASN1Encodable getObjectParser(int tag, boolean isExplicit)
        throws IOException;
}
