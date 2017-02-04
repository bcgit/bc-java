package org.bouncycastle.tls;

/**
 * Base interface for a carrier object for a TLS session.
 */
public interface TlsSession
{
    SessionParameters exportSessionParameters();

    byte[] getSessionID();

    void invalidate();

    boolean isResumable();
}
