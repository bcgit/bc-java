package org.bouncycastle.est;

import java.io.IOException;
import java.io.OutputStream;

/**
 * ESTClientRequestIdempotentInputSource, implementations of this will be called when the HTTP preamble
 * (Request-Line and Request Headers) have been written to the source.
 * Implementations are required to ensure the headers for Content-length are appropriately set
 * before writing data.
 *
 * Implementation may be called more than once if the server responds (401) and requires Authentication.
 * Subsequent calls must be idempotent.
 */
public interface ESTClientRequestIdempotentInputSource
{
    void ready(OutputStream os)
        throws IOException;
}
