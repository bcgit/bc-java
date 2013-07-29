package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Everybody implementing this has readObject() producing {@link ASN1Encodable}.
 */
public interface ASN1SequenceParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Read an object from the input stream.
     * @throws IOException for bad input stream.
     */
    ASN1Encodable readObject()
        throws IOException;
}
