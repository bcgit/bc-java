package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Interface for picking up an in-memory representation of the ASN.1 object.
 */
public interface InMemoryRepresentable
{
    /**
     * Get the in-memory representation of the ASN.1 object.
     * @throws IOException for bad input data.
     */
    ASN1Primitive getLoadedObject()
        throws IOException;
}
