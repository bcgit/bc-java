package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.function.BiFunction;

import javax.net.ssl.SSLSocket;

class ProvSSLSocketDirect_9
    extends ProvSSLSocketDirect
{
    /** This constructor is the one used (only) by ProvSSLServerSocket */
    ProvSSLSocketDirect_9(ProvSSLContextSpi context, ContextData contextData, boolean enableSessionCreation,
        boolean useClientMode, ProvSSLParameters sslParameters)
    {
        super(context, contextData, enableSessionCreation, useClientMode, sslParameters);
    }

    protected ProvSSLSocketDirect_9(ProvSSLContextSpi context, ContextData contextData)
    {
        super(context, contextData);
    }

    protected ProvSSLSocketDirect_9(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port,
        InetAddress clientAddress, int clientPort) throws IOException
    {
        super(context, contextData, address, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketDirect_9(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port)
        throws IOException
    {
        super(context, contextData, address, port);
    }

    protected ProvSSLSocketDirect_9(ProvSSLContextSpi context, ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        super(context, contextData, host, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketDirect_9(ProvSSLContextSpi context, ContextData contextData, String host, int port)
        throws IOException, UnknownHostException
    {
        super(context, contextData, host, port);
    }

    @Override
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<SSLSocket, List<String>, String> selector)
    {
        sslParameters.setSocketAPSelector(JsseUtils_9.importAPSelector(selector));
    }

    @Override
    public synchronized BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector()
    {
        return JsseUtils_9.exportAPSelector(sslParameters.getSocketAPSelector());
    }
}
