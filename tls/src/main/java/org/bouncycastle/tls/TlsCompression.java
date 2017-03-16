package org.bouncycastle.tls;

import java.io.OutputStream;

/**
 * Base interface for a compression operator.
 */
public interface TlsCompression
{
    /**
     * Return an output stream that writes compressed data to the passed in stream.
     *
     * @param output the stream to write compressed data to.
     * @return a target output stream to write the data to be compressed to.
     */
    OutputStream compress(OutputStream output);

    /**
     * Return an output stream that writes uncompressed data to the passed in stream.
     *
     * @param output the stream to write uncompressed data to.
     * @return a target output stream to write the data to be uncompressed to.
     */
    OutputStream decompress(OutputStream output);
}
