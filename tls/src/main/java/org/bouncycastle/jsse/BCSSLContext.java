package org.bouncycastle.jsse;

/**
 * A BCJSSE-specific interface to expose extended functionality of a {@link javax.net.ssl.SSLContext}.
 * <p>
 * An instance describes a single initialization of the SSLContext: if the SSLContext is subsequently
 * re-initialized, an instance obtained earlier continues to describe the earlier initialization. Use
 * {@link org.bouncycastle.jsse.util.ContextUtil#getBCSSLContext(javax.net.ssl.SSLContext)} to obtain an
 * instance for the current initialization.
 * </p>
 */
public interface BCSSLContext
{
    /**
     * Returns a {@link BCSSLParameters} with properties reflecting the default configuration for
     * connections in the given mode. This differs from
     * {@link javax.net.ssl.SSLContext#getDefaultSSLParameters()} in two ways:
     * <ul>
     * <li>it includes the default values of the BC-specific properties, which cannot be reported
     * through {@link javax.net.ssl.SSLParameters};</li>
     * <li>the defaults for either client or server mode can be requested, whereas the SSLContext
     * method always reports the client-mode defaults.</li>
     * </ul>
     *
     * @param isClient
     *            whether to return the defaults for client mode (<code>true</code>) or server mode
     *            (<code>false</code>)
     * @return the default {@link BCSSLParameters parameters}
     */
    BCSSLParameters getDefaultParameters(boolean isClient);

    /**
     * Returns a {@link BCSSLParameters} with properties reflecting the supported configuration for
     * connections in the given mode. This differs from
     * {@link javax.net.ssl.SSLContext#getSupportedSSLParameters()} in the same two ways that
     * {@link #getDefaultParameters(boolean)} differs from
     * {@link javax.net.ssl.SSLContext#getDefaultSSLParameters()}.
     *
     * @param isClient
     *            whether to return the supported parameters for client mode (<code>true</code>) or
     *            server mode (<code>false</code>)
     * @return the supported {@link BCSSLParameters parameters}
     */
    BCSSLParameters getSupportedParameters(boolean isClient);
}
