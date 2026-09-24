package org.bouncycastle.jsse;

/**
 * A BCJSSE-specific interface to expose extended functionality on {@link javax.net.ssl.SSLSessionContext}
 * implementations.
 */
public interface BCSSLSessionContext
{
    /**
     * Returns the {@link BCSSLContext} describing the initialization of the
     * {@link javax.net.ssl.SSLContext} that this session context belongs to.
     *
     * @return the {@link BCSSLContext} for this session context
     */
    BCSSLContext getBCSSLContext();
}
