package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * Base interface for an object sending and receiving DTLS data.
 */
public interface DatagramTransport
{
    int getReceiveLimit()
        throws IOException;

    int getSendLimit()
        throws IOException;

    int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException;

    void send(byte[] buf, int off, int len)
        throws IOException;

    void close()
        throws IOException;
}
