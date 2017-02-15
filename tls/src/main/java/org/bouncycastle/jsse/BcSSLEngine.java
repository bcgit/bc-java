package org.bouncycastle.jsse;

/**
 * A BCJSSE-specific interface to expose extended functionality on {@link SSLEngine}
 * implementations.
 */
public interface BcSSLEngine
{
    /**
     * Returns an accessor for extended SSL connection data. Unlike BcSSLSocket.getSession() this
     * method does not block until handshaking is complete. Until the initial handshake has
     * completed, this method returns <c>null</c>.
     * 
     * @return A {@link BcSSLConnection} instance.
     */
    BcSSLConnection getConnection();
}
