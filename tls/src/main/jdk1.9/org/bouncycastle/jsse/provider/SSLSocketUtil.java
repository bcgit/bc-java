package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

abstract class SSLSocketUtil
{
    /** This factory method is the one used (only) by ProvSSLServerSocket */
    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, boolean enableSessionCreation,
        boolean useClientMode, ProvSSLParameters sslParameters)
    {
        return new ProvSSLSocketDirect_9(context, contextData, enableSessionCreation, useClientMode, sslParameters);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData)
    {
        return new ProvSSLSocketDirect_9(context, contextData);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port,
        InetAddress clientAddress, int clientPort) throws IOException
    {
        return new ProvSSLSocketDirect_9(context, contextData, address, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port)
        throws IOException
    {
        return new ProvSSLSocketDirect_9(context, contextData, address, port);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        return new ProvSSLSocketDirect_9(context, contextData, host, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, String host, int port) throws IOException, UnknownHostException
    {
        return new ProvSSLSocketDirect_9(context, contextData, host, port);
    }

    static ProvSSLSocketWrap create(ProvSSLContextSpi context, ContextData contextData, Socket s, InputStream consumed, boolean autoClose)
        throws IOException
    {
        return new ProvSSLSocketWrap_9(context, contextData, s, consumed, autoClose);
    }

    static ProvSSLSocketWrap create(ProvSSLContextSpi context, ContextData contextData, Socket s, String host, int port, boolean autoClose)
        throws IOException
    {
        return new ProvSSLSocketWrap_9(context, contextData, s, host, port, autoClose);
    }

    static BCExtendedSSLSession importHandshakeSession(SSLSocket sslSocket)
    {
        if (sslSocket instanceof BCSSLSocket)
        {
            return ((BCSSLSocket)sslSocket).getBCHandshakeSession();
        }
        if (null != sslSocket)
        {
            SSLSession sslSession = sslSocket.getHandshakeSession();
            if (null != sslSession)
            {
                return SSLSessionUtil.importSSLSession(sslSession);
            }
        }
        return null;
    }

    static BCSSLParameters importSSLParameters(SSLSocket sslSocket)
    {
        if (sslSocket instanceof BCSSLSocket)
        {
            return ((BCSSLSocket)sslSocket).getParameters();
        }
        if (null != sslSocket)
        {
            SSLParameters sslParameters = sslSocket.getSSLParameters();
            if (null != sslParameters)
            {
                return SSLParametersUtil.importSSLParameters(sslParameters);
            }
        }
        return null;
    }
}
