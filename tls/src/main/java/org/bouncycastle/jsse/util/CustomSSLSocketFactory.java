package org.bouncycastle.jsse.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

public class CustomSSLSocketFactory extends SSLSocketFactory
{
    protected final SSLSocketFactory delegate;

    public CustomSSLSocketFactory(SSLSocketFactory delegate)
    {
        if (null == delegate)
        {
            throw new NullPointerException("'delegate' cannot be null");
        }

        this.delegate = delegate;
    }

    @Override
    public Socket createSocket() throws IOException
    {
        return configureSocket(delegate.createSocket());
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
        return configureSocket(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException
    {
        return configureSocket(delegate.createSocket(address, port, localAddress, localPort));
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException
    {
        return configureSocket(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException, UnknownHostException
    {
        return configureSocket(delegate.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException
    {
        return configureSocket(delegate.createSocket(s, consumed, autoClose));
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
    {
        return configureSocket(delegate.createSocket(s, host, port, autoClose));
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return delegate.getSupportedCipherSuites();
    }

    protected Socket configureSocket(Socket s)
    {
        return s;
    }
}
