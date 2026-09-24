package org.bouncycastle.jsse;

/**
 * A BCJSSE-specific interface to expose extended functionality on {@link javax.net.ssl.SSLServerSocket}
 * implementations.
 */
public interface BCSSLServerSocket
{
    /**
     * Returns a {@link BCSSLParameters} with properties reflecting the configuration that will be
     * applied to newly accepted connections.
     *
     * @return the current {@link BCSSLParameters parameters}
     */
    BCSSLParameters getParameters();

    /**
     * Sets the parameters for newly accepted connections according to the properties in a
     * {@link BCSSLParameters}. Connections already accepted are unaffected.
     * <p>
     * Note that many properties set to null will be ignored, which will leave the corresponding
     * settings unchanged. However, the newer properties signatureSchemes, signatureSchemesCert,
     * namedGroups and earlyKeyShares are always applied, and setting one of them to null restores the
     * default behaviour for that property.
     * </p>
     *
     * @param parameters
     *            the {@link BCSSLParameters parameters} to set
     * @throws IllegalArgumentException
     *             if the setEnabledCipherSuites() or the setEnabledProtocols() call fails
     */
    void setParameters(BCSSLParameters parameters);
}
