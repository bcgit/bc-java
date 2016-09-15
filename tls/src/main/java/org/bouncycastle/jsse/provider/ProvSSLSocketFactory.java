package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

class ProvSSLSocketFactory
    extends SSLSocketFactory
{
    ProvSSLSocketFactory()
    {
    }

//    @Override
//    public Socket createSocket() throws IOException
//    {
//        return super.createSocket();
//    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException, UnknownHostException
    {
        throw new UnsupportedOperationException();
    }

//    @Override
//    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException
//    {
//        return super.createSocket(s, consumed, autoClose);
//    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        throw new UnsupportedOperationException();
    }
}
