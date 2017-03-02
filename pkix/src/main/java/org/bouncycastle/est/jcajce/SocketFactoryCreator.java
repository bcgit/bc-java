package org.bouncycastle.est.jcajce;


import javax.net.ssl.SSLSocketFactory;

/**
 * Implementations provide SSL socket factories.
 */
public interface SocketFactoryCreator
{
    SSLSocketFactory createFactory()
        throws Exception;

    boolean isTrusted();
}
