package org.bouncycastle.jsse;

import javax.net.ssl.SSLSession;

/**
 * A BCJSSE-specific interface providing access to extended connection-specific functionality.
 */
public interface BCSSLConnection
{
    /**
     * Request TLS Channel Bindings for this connection. See
     * <a href="https://tools.ietf.org/html/rfc5929">RFC 5929</a> for details.
     * 
     * @param channelBinding
     *            An IANA-registered "Channel-binding unique prefix" valid for TLS e.g. "tls-unique".
     * @return A copy of the channel binding data as a {@link byte[]}.
     */
    byte[] getChannelBinding(String channelBinding);

    /**
     * Returns the SSL Session in use by this connection
     * @return The {@link SSLSession}.
     */
    SSLSession getSession();
}
