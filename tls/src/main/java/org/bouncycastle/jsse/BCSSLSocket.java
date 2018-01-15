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

    /**
     * Returns a {@link BCSSLParameters} with properties reflecting the current configuration.
     * @return the current {@link BCSSLParameters parameters}
     */
    BCSSLParameters getParameters();

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
