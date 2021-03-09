package org.bouncycastle.jsse.util;

import java.net.Socket;
import java.net.URL;
import java.util.Collections;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

public class SNISocketFactory extends CustomSSLSocketFactory
{
    private static final Logger LOG = Logger.getLogger(SNISocketFactory.class.getName());

    protected static final ThreadLocal<SNISocketFactory> threadLocal = new ThreadLocal<SNISocketFactory>();

    /**
     * Signature matches {@link SSLSocketFactory#getDefault()} so that it can be
     * used with e.g. the "java.naming.ldap.factory.socket" property or similar.
     * 
     * @see #call(Callable)
     */
    public static SocketFactory getDefault()
    {
        SSLSocketFactory sslSocketFactory = threadLocal.get();
        if (null != sslSocketFactory)
        {
            return sslSocketFactory;
        }

        return SSLSocketFactory.getDefault();
    }

    protected final URL url;

    public SNISocketFactory(SSLSocketFactory delegate, URL url)
    {
        super(delegate);

        this.url = url;
    }

    /**
     * Calls a {@link Callable} in a context where this class's static
     * {@link #getDefault()} method will return this {@link SNISocketFactory}.
     */
    public <V> V call(Callable<V> callable) throws Exception
    {
        try
        {
            threadLocal.set(this);

            return callable.call();
        }
        finally
        {
            threadLocal.remove();
        }
    }

    @Override
    protected Socket configureSocket(Socket s)
    {
        if (s instanceof BCSSLSocket)
        {
            BCSSLSocket ssl = (BCSSLSocket)s;

            BCSNIHostName sniHostName = getBCSNIHostName();
            if (null != sniHostName)
            {
                LOG.fine("Setting SNI on socket: " + sniHostName);

                BCSSLParameters sslParameters = new BCSSLParameters();
                sslParameters.setServerNames(Collections.<BCSNIServerName> singletonList(sniHostName));

                ssl.setParameters(sslParameters);
            }
        }
        return s;
    }

    protected BCSNIHostName getBCSNIHostName()
    {
        return SNIUtil.getBCSNIHostName(url);
    }
}
