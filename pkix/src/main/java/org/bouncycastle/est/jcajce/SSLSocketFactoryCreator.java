package org.bouncycastle.est.jcajce;


import javax.net.ssl.SSLSocketFactory;

/**
 * Implementations provide SSL socket factories.
 */
public interface SSLSocketFactoryCreator
{
    SSLSocketFactory createFactory()
        throws Exception;

    boolean isTrusted();
}
