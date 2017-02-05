package org.bouncycastle.est;

/**
 * Verify the host name is as expected after the SSL Handshake has been completed.
 *
 * @param <T>
 */
public interface TLSHostNameAuthorizer<T>
{
    Boolean authorise(String name, T context);
}
