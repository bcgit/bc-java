package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

abstract class SSLSocketUtil
{
    private static AtomicInteger threadNumber = new AtomicInteger();

    /** This factory method is the one used (only) by ProvSSLServerSocket */
    static ProvSSLSocketDirect create(ContextData contextData, boolean enableSessionCreation,
        boolean useClientMode, ProvSSLParameters sslParameters)
    {
        return new ProvSSLSocketDirect_9(contextData, enableSessionCreation, useClientMode, sslParameters);
    }

    static ProvSSLSocketDirect create(ContextData contextData)
    {
        return new ProvSSLSocketDirect_9(contextData);
    }

    static ProvSSLSocketDirect create(ContextData contextData, InetAddress address, int port,
        InetAddress clientAddress, int clientPort) throws IOException
    {
        return new ProvSSLSocketDirect_9(contextData, address, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ContextData contextData, InetAddress address, int port)
        throws IOException
    {
        return new ProvSSLSocketDirect_9(contextData, address, port);
    }

    static ProvSSLSocketDirect create(ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        return new ProvSSLSocketDirect_9(contextData, host, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ContextData contextData, String host, int port) throws IOException, UnknownHostException
    {
        return new ProvSSLSocketDirect_9(contextData, host, port);
    }

    static ProvSSLSocketWrap create(ContextData contextData, Socket s, InputStream consumed, boolean autoClose)
        throws IOException
    {
        return new ProvSSLSocketWrap_9(contextData, s, consumed, autoClose);
    }

    static ProvSSLSocketWrap create(ContextData contextData, Socket s, String host, int port, boolean autoClose)
        throws IOException
    {
        return new ProvSSLSocketWrap_9(contextData, s, host, port, autoClose);
    }

    static void handshakeCompleted(Runnable notifyRunnable)
    {
        String name = "BCJSSE-HandshakeCompleted-" + Integer.toUnsignedString(threadNumber.getAndIncrement());

        // Can't be a daemon thread
        new Thread(null, notifyRunnable, name, 0, false).start();
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
        if (null == sslSocket)
        {
            return null;
        }

        SSLParameters sslParameters = sslSocket.getSSLParameters();
        if (null == sslParameters)
        {
            throw new RuntimeException("SSLSocket.getSSLParameters returned null");
        }

        return SSLParametersUtil.importSSLParameters(sslParameters);
    }
}
