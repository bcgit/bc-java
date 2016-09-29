package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLEngine;
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
        SSLEngine engine = context.engineCreateSSLEngine();
        return new ProvSSLSocket(engine);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
        SSLEngine engine = context.engineCreateSSLEngine(host.getHostName(), port);
        return new ProvSSLSocket(engine, host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException
    {
        SSLEngine engine = context.engineCreateSSLEngine(address.getHostName(), port);
        return new ProvSSLSocket(engine, address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException
    {
        SSLEngine engine = context.engineCreateSSLEngine(host, port);
        return new ProvSSLSocket(engine, host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException, UnknownHostException
    {
        SSLEngine engine = context.engineCreateSSLEngine(host, port);
        return new ProvSSLSocket(engine, host, port, localHost, localPort);
    }

    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException
    {
        /*
         * TODO[tls-ops] "Creates a server mode Socket layered over an existing connected socket,
         * and is able to read data which has already been consumed/removed from the Socket's
         * underlying InputStream."
         */
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
    {
        /*
         * TODO[tls-ops]
         * "Returns a socket layered over an existing socket connected to the named host, at the given port."
         */
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
