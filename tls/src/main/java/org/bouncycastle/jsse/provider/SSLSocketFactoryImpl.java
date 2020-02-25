package org.bouncycastle.jsse.provider;

/**
 * Public class with a public default constructor, for use with the "ssl.SocketFactory.provider"
 * property in the java.security file.
 */
public class SSLSocketFactoryImpl
    extends ProvSSLSocketFactory
{
    public SSLSocketFactoryImpl() throws Exception
    {
        super(DefaultSSLContextSpi.getDefaultInstance().getContextData());
    }
}
