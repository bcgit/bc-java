package com.github.gv2011.bcasn;

import java.io.InputStream;

/**
 * A basic parser for an OCTET STRING object
 */
public interface ASN1OctetStringParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Return the content of the OCTET STRING as an InputStream.
     *
     * @return an InputStream representing the OCTET STRING's content.
     */
    public InputStream getOctetStream();
}
