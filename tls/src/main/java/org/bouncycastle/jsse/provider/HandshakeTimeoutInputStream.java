package org.bouncycastle.jsse.provider;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;

import org.bouncycastle.tls.TlsTimeoutException;

/**
 * Enforces a total (wall-clock) timeout across a complete handshake for the blocking socket
 * path, mirroring the semantics {@code DTLSReliableHandshake} already provides for DTLS.
 * <p>
 * The blocking stream-TLS handshake reads records from a plain {@link InputStream}, where the
 * only available timeout is the socket's per-read {@code SO_TIMEOUT}. A per-read timeout only
 * aborts a fully stalled peer; it does not bound the total handshake time, so a peer that drips
 * bytes slower than the handshake completes (but faster than {@code SO_TIMEOUT}) can hold the
 * handshake open indefinitely. This stream shrinks {@code SO_TIMEOUT} to the remaining budget
 * before each read, so the elapsed handshake time cannot exceed the configured deadline.
 * <p>
 * Once the handshake completes (or fails) {@link #deactivate()} restores the caller's original
 * {@code SO_TIMEOUT} and the stream becomes a transparent pass-through for application data.
 */
class HandshakeTimeoutInputStream
    extends FilterInputStream
{
    private final Socket socket;
    private final long deadline;
    private final int savedSoTimeout;

    private boolean active = true;

    HandshakeTimeoutInputStream(InputStream in, Socket socket, int timeoutMillis)
        throws IOException
    {
        super(in);

        this.socket = socket;
        this.savedSoTimeout = socket.getSoTimeout();
        this.deadline = System.currentTimeMillis() + timeoutMillis;
    }

    public int read()
        throws IOException
    {
        byte[] b = new byte[1];
        int n = read(b, 0, 1);
        return n < 0 ? -1 : (b[0] & 0xFF);
    }

    public int read(byte[] b, int off, int len)
        throws IOException
    {
        if (active)
        {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0)
            {
                throw new TlsTimeoutException("Handshake timed out");
            }

            int budget = (int)Math.min(remaining, Integer.MAX_VALUE);

            // Never weaken a tighter per-read SO_TIMEOUT the caller may have set
            int perRead = savedSoTimeout > 0 ? Math.min(savedSoTimeout, budget) : budget;

            socket.setSoTimeout(Math.max(1, perRead));
        }

        try
        {
            return super.read(b, off, len);
        }
        catch (SocketTimeoutException e)
        {
            if (active && System.currentTimeMillis() >= deadline)
            {
                throw new TlsTimeoutException("Handshake timed out");
            }

            // A caller-supplied per-read SO_TIMEOUT fired, not the handshake deadline
            throw e;
        }
    }

    void deactivate()
    {
        if (active)
        {
            active = false;

            try
            {
                socket.setSoTimeout(savedSoTimeout);
            }
            catch (IOException e)
            {
                // Best-effort restore: if the handshake failed the socket may already be closed,
                // in which case there is nothing to restore and we must not mask the real cause.
            }
        }
    }
}
