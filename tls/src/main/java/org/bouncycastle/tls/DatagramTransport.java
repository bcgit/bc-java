package org.bouncycastle.tls;

import java.io.IOException;

/**
 * Base interface for an object sending and receiving DTLS data.
 */
public interface DatagramTransport extends DatagramSender
{
    int getReceiveLimit()
        throws IOException;

    int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException;

    void close()
        throws IOException;
}
