package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

class ProvSSLSocketFactory
    extends SSLSocketFactory
{
    protected final ProvSSLContextSpi context;

    ProvSSLSocketFactory(ProvSSLContextSpi context)
    {
        super();

        this.context = context;
    }

    @Override
    public Socket createSocket() throws IOException
    {
        return SSLSocketUtil.create(context, context.createContextData());
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
        return SSLSocketUtil.create(context, context.createContextData(), host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException
    {
        return SSLSocketUtil.create(context, context.createContextData(), address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException
    {
        return SSLSocketUtil.create(context, context.createContextData(), host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException, UnknownHostException
    {
        return SSLSocketUtil.create(context, context.createContextData(), host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException
    {
        return SSLSocketUtil.create(context, context.createContextData(), s, consumed, autoClose);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
    {
        return SSLSocketUtil.create(context, context.createContextData(), s, host, port, autoClose);
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return context.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return context.getSupportedCipherSuites();
    }
}
