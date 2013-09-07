package org.bouncycastle.asn1;

import java.io.InputStream;

/**
 * Everybody implementing this has getOctetStream() returning an InputStream.
 */
public interface ASN1OctetStringParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Get the object content in a generic InputStream.
     */
    public InputStream getOctetStream();
}
