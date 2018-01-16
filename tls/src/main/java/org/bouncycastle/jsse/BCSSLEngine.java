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
