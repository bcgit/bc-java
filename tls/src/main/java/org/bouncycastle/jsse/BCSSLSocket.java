package org.bouncycastle.jsse;

/**
 * A BCJSSE-specific interface to expose extended functionality on {@link javax.net.ssl.SSLSocket}
 * implementations.
 */
public interface BCSSLSocket
{
    /**
     * Returns an accessor for extended SSL connection data. This method will initiate the initial
     * handshake if necessary and then block until the handshake has been established. If an error
     * occurs during the initial handshake, this method returns <code>null</code>.
     * 
     * @return A {@link BCSSLConnection} instance.
     */
    BCSSLConnection getConnection();
}
