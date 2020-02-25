package org.bouncycastle.jsse.provider;

/**
 * Public class with a public default constructor, for use with the "ssl.ServerSocketFactory.provider"
 * property in the java.security file.
 */
public class SSLServerSocketFactoryImpl
    extends ProvSSLServerSocketFactory
{
    public SSLServerSocketFactoryImpl() throws Exception
    {
        super(DefaultSSLContextSpi.getDefaultInstance().getContextData());
    }
}
