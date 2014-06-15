package org.bouncycastle.openpgp;

import java.io.IOException;

/**
 * Callback interface for generators that produce a stream to be informed when the stream has been
 * closed by the client.
 */
interface StreamGenerator
{
    /**
     * Signal that the stream has been closed.
     */
    void close()
        throws IOException;
}
