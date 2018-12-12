package org.bouncycastle.jsse;

/**
 * A BCJSSE-specific interface providing access to extended connection-specific functionality.
 */
public interface BCSSLConnection
{
    /**
     * Returns the application protocol negotiated for this connection, or an empty {@code String}
     * if none was negotiated. See <a href="https://tools.ietf.org/html/rfc7301">RFC 7301</a> for
     * details.
     * 
     * @return The negotiated application protocol, or an empty {@code String}.
     */
    String getApplicationProtocol();

    /**
     * Request TLS Channel Bindings for this connection. See
     * <a href="https://tools.ietf.org/html/rfc5929">RFC 5929</a> for details.
     * 
     * @param channelBinding
     *            An IANA-registered "Channel-binding unique prefix" valid for TLS e.g.
     *            "tls-unique" or "tls-server-end-point".
     * @return A copy of the channel binding data as a {@link byte[]}, or null if the binding is
     *         unavailable for this connection.
     */
    byte[] getChannelBinding(String channelBinding);

    /**
     * Returns the SSL session in use by this connection
     * @return The {@link BCExtendedSSLSession}.
     */
    BCExtendedSSLSession getSession();
}
