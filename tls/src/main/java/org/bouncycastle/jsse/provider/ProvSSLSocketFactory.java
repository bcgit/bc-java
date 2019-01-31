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
//        SSLEngine engine = context.engineCreateSSLEngine();
//        return new ProvSSLSocket(engine);
        return new ProvSSLSocketDirect(context, context.createContextData());
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
//        SSLEngine engine = context.engineCreateSSLEngine(host.getHostName(), port);
//        return new ProvSSLSocket(engine, host, port);
        return new ProvSSLSocketDirect(context, context.createContextData(), host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException
    {
//        SSLEngine engine = context.engineCreateSSLEngine(address.getHostName(), port);
//        return new ProvSSLSocket(engine, address, port, localAddress, localPort);
        return new ProvSSLSocketDirect(context, context.createContextData(), address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException
    {
//        SSLEngine engine = context.engineCreateSSLEngine(host, port);
//        return new ProvSSLSocket(engine, host, port);
        return new ProvSSLSocketDirect(context, context.createContextData(), host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
        throws IOException, UnknownHostException
    {
//        SSLEngine engine = context.engineCreateSSLEngine(host, port);
//        return new ProvSSLSocket(engine, host, port, localHost, localPort);
        return new ProvSSLSocketDirect(context, context.createContextData(), host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException
    {
        return new ProvSSLSocketWrap(context, context.createContextData(), s, consumed, autoClose);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
    {
        return new ProvSSLSocketWrap(context, context.createContextData(), s, host, port, autoClose);
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
