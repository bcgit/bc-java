package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Interface for parse of ApplicationSpecific objects.
 */
public interface ASN1ApplicationSpecificParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Read an object from the input stream.
     * @throws IOException for bad input stream.
     */
    ASN1Encodable readObject()
        throws IOException;
}
