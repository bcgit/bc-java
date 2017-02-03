package org.bouncycastle.est;


/**
 * A client provider is responsible for creating an ESTClient instance.
 */
public interface ESTClientProvider
{
    ESTClient makeHttpClient()
        throws Exception;

    /**
     * Return true if the client is presently configured to verify the server.
     * @return true = verifying server.
     */
    boolean isTrusted();
}
