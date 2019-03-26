package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
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
    private static final Method getHandshakeSession;
    private static final Method getSSLParameters;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("javax.net.ssl.SSLSocket");

        getHandshakeSession = ReflectionUtil.findMethod(methods, "getHandshakeSession");
        getSSLParameters = ReflectionUtil.findMethod(methods, "getSSLParameters");
    }

    /** This factory method is the one used (only) by ProvSSLServerSocket */
    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, boolean enableSessionCreation,
        boolean useClientMode, ProvSSLParameters sslParameters)
    {
        return new ProvSSLSocketDirect(context, contextData, enableSessionCreation, useClientMode, sslParameters);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData)
    {
        return new ProvSSLSocketDirect(context, contextData);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port,
        InetAddress clientAddress, int clientPort) throws IOException
    {
        return new ProvSSLSocketDirect(context, contextData, address, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port)
        throws IOException
    {
        return new ProvSSLSocketDirect(context, contextData, address, port);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        return new ProvSSLSocketDirect(context, contextData, host, port, clientAddress, clientPort);
    }

    static ProvSSLSocketDirect create(ProvSSLContextSpi context, ContextData contextData, String host, int port) throws IOException, UnknownHostException
    {
        return new ProvSSLSocketDirect(context, contextData, host, port);
    }

    static ProvSSLSocketWrap create(ProvSSLContextSpi context, ContextData contextData, Socket s, InputStream consumed, boolean autoClose)
        throws IOException
    {
        return new ProvSSLSocketWrap(context, contextData, s, consumed, autoClose);
    }

    static ProvSSLSocketWrap create(ProvSSLContextSpi context, ContextData contextData, Socket s, String host, int port, boolean autoClose)
        throws IOException
    {
        return new ProvSSLSocketWrap(context, contextData, s, host, port, autoClose);
    }

    static BCExtendedSSLSession importHandshakeSession(SSLSocket sslSocket)
    {
        if (sslSocket instanceof BCSSLSocket)
        {
            return ((BCSSLSocket)sslSocket).getBCHandshakeSession();
        }
        if (null != sslSocket && null != getHandshakeSession)
        {
            try
            {
                SSLSession sslSession = (SSLSession)ReflectionUtil.invokeGetter(sslSocket, getHandshakeSession);
                if (null != sslSession)
                {
                    return SSLSessionUtil.importSSLSession(sslSession);
                }
            }
            catch (Exception e)
            {
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
        if (null != sslSocket && null != getSSLParameters)
        {
            try
            {
                SSLParameters sslParameters = (SSLParameters)ReflectionUtil.invokeGetter(sslSocket, getSSLParameters);
                if (null != sslParameters)
                {
                    return SSLParametersUtil.importSSLParameters(sslParameters);
                }
            }
            catch (Exception e)
            {
            }
        }
        return null;
    }
}
