package org.bouncycastle.jsse.util;

import java.net.Socket;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.jsse.BCSSLSocket;

public class SetHostSocketFactory extends CustomSSLSocketFactory
{
    private static final Logger LOG = Logger.getLogger(SetHostSocketFactory.class.getName());

    protected static final ThreadLocal<SetHostSocketFactory> threadLocal = new ThreadLocal<SetHostSocketFactory>();

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

    protected final String host;

    public SetHostSocketFactory(SSLSocketFactory delegate, URL url)
    {
        this(delegate, url == null ? null : url.getHost());
    }

    public SetHostSocketFactory(SSLSocketFactory delegate, String host)
    {
        super(delegate);

        this.host = host;
    }

    /**
     * Calls a {@link Callable} in a context where this class's static
     * {@link #getDefault()} method will return this {@link SetHostSocketFactory}.
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
        if (host != null && s instanceof BCSSLSocket)
        {
            BCSSLSocket ssl = (BCSSLSocket)s;

            LOG.fine("Setting host on socket: " + host);

            ssl.setHost(host);
        }
        return s;
    }
}
