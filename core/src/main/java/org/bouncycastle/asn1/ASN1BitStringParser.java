package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * A basic parser for a BIT STRING object
 */
public interface ASN1BitStringParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Return an InputStream representing the contents of the BIT STRING. The final
     * byte, if any, may include pad bits. See {@link #getPadBits()}.
     *
     * @return an InputStream with its source as the BIT STRING content.
     */
    public InputStream getBitStream() throws IOException;

    /**
     * Return an InputStream representing the contents of the BIT STRING, where the
     * content is expected to be octet-aligned (this will be automatically checked
     * during parsing).
     *
     * @return an InputStream with its source as the BIT STRING content.
     */
    public InputStream getOctetStream() throws IOException;

    /**
     * Return the number of pad bits, if any, in the final byte, if any, read from
     * {@link #getBitStream()}. This number is in the range zero to seven. That
     * number of the least significant bits of the final byte, if any, are not part
     * of the contents and should be ignored. NOTE: Must be called AFTER the stream
     * has been fully processed. (Does not need to be called if
     * {@link #getOctetStream()} was used instead of {@link #getBitStream()}).
     *
     * @return the number of pad bits. In the range zero to seven.
     */
    public int getPadBits();
}
