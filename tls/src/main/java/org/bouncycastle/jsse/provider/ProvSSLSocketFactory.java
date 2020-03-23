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
    protected final ContextData contextData;

    ProvSSLSocketFactory(ContextData contextData)
    {
        super();

        this.contextData = contextData;
    }

    @Override
    public Socket createSocket() throws IOException
    {
        return SSLSocketUtil.create(contextData);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
        return SSLSocketUtil.create(contextData, host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException
    {
        return SSLSocketUtil.create(contextData, address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException
    {
        return SSLSocketUtil.create(contextData, host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException, UnknownHostException
    {
        return SSLSocketUtil.create(contextData, host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException
    {
        return SSLSocketUtil.create(contextData, s, consumed, autoClose);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
    {
        return SSLSocketUtil.create(contextData, s, host, port, autoClose);
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return contextData.getContext().getDefaultCipherSuites(true);
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return contextData.getContext().getSupportedCipherSuites();
    }
}
