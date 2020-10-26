package org.bouncycastle.jsse;

import java.io.IOException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * A BCJSSE-specific interface to expose extended functionality on {@link javax.net.ssl.SSLSocket}
 * implementations.
 */
public interface BCSSLSocket
{
    void connect(String host, int port, int timeout) throws IOException;

    String getApplicationProtocol();

    BCApplicationProtocolSelector<SSLSocket> getBCHandshakeApplicationProtocolSelector();

    void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLSocket> selector);

    void setBCSessionToResume(BCExtendedSSLSession session);

    BCExtendedSSLSession getBCHandshakeSession();

    BCExtendedSSLSession getBCSession();

    /**
     * Returns an accessor for extended SSL connection data. This method will initiate the initial
     * handshake if necessary and then block until the handshake has been established. If an error
     * occurs during the initial handshake, this method returns <code>null</code>.
     * 
     * @return A {@link BCSSLConnection} instance.
     */
    BCSSLConnection getConnection();

    String getHandshakeApplicationProtocol();

    /**
     * Returns a {@link BCSSLParameters} with properties reflecting the current configuration.
     * @return the current {@link BCSSLParameters parameters}
     */
    BCSSLParameters getParameters();

    /**
     * Allows explicit setting of the 'host' {@link String} when the {@link SocketFactory} methods
     * that include it as an argument are not used.
     * <p>
     * Must be called prior to attempting to connect the socket to have any effect.
     * </p>
     *
     * @param host
     *            the server host name with which to connect, or <code>null</code> for the loopback
     *            address.
     */
    void setHost(String host);

    /**
     * Sets parameters according to the properties in a {@link BCSSLParameters}.
     * <p>
     * Note that any properties set to null will be ignored, which will leave the corresponding
     * settings unchanged.
     * </p>
     *
     * @param parameters
     *            the {@link BCSSLParameters parameters} to set
     * @throws IllegalArgumentException
     *             if the cipherSuites or protocols properties contain unsupported values
     */
    void setParameters(BCSSLParameters parameters);
}
