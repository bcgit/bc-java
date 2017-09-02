package org.bouncycastle.jsse;

/**
 * A BCJSSE-specific interface to expose extended functionality on {@link javax.net.ssl.SSLEngine}
 * implementations.
 */
public interface BCSSLEngine
{
    /**
     * Returns an accessor for extended SSL connection data. Unlike
     * {@link BCSSLSocket#getConnection} this method does not block until handshaking is complete.
     * Until the initial handshake has completed, this method returns <code>null</code>.
     * 
     * @return A {@link BCSSLConnection} instance.
     */
    BCSSLConnection getConnection();
}
