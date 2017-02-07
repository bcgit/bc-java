package org.bouncycastle.est;

/**
 * Verify the host name is as expected after the SSL Handshake has been completed.
 *
 * @param <T>
 */
public interface ESTHostNameAuthorizer<T>
{
    /**
     * Verify the passed in host name according to the context object.
     *
     * @param name    name of the host to be verified.
     * @param context context object to do the verification under.
     * @return true if name verified, false otherwise.
     */
    boolean verified(String name, T context);
}
