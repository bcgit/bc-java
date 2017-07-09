package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCSSLConnection;

class ProvSSLSocket
    extends ProvSSLSocketBase
{
    protected final ProvSSLEngine engine;

    protected ProvSSLSocket(ProvSSLEngine engine)
    {
        super();

        this.engine = engine;
    }

    protected ProvSSLSocket(ProvSSLEngine engine, InetAddress address, int port) throws IOException
    {
        super(address, port);

        this.engine = engine;
    }

    protected ProvSSLSocket(ProvSSLEngine engine, InetAddress address, int port, InetAddress clientAddress, int clientPort) throws IOException
    {
        super(address, port, clientAddress, clientPort);

        this.engine = engine;
    }

    protected ProvSSLSocket(ProvSSLEngine engine, String host, int port) throws IOException, UnknownHostException
    {
        super(host, port);

        this.engine = engine;
    }

    protected ProvSSLSocket(ProvSSLEngine engine, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        super(host, port, clientAddress, clientPort);

        this.engine = engine;
    }

    @Override
    public synchronized void close() throws IOException
    {
        // TODO[jsse] See javadoc for full discussion of SSLEngine closure

        engine.closeOutbound();

        // TODO[jsse]
        // - Flush output by calling engine.wrap while not CLOSED 
        // - Check under what circumstances need to call engine.closeInbound

        super.close();
    }

    public BCSSLConnection getConnection()
    {
        /*
         * TODO[jsse] This should actually block until handshake complete (and maybe start it)
         */
        return engine.getConnection();
    }

    @Override
    public String[] getEnabledCipherSuites()
    {
        return engine.getEnabledCipherSuites();
    }

    @Override
    public String[] getEnabledProtocols()
    {
        return engine.getEnabledProtocols();
    }

    @Override
    public boolean getEnableSessionCreation()
    {
        return engine.getEnableSessionCreation();
    }

    @Override
    public SSLSession getHandshakeSession()
    {
        return engine.getHandshakeSession();
    }

    @Override
    public InputStream getInputStream() throws IOException
    {
//        return super.getInputStream();
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean getNeedClientAuth()
    {
        return engine.getNeedClientAuth();
    }

    @Override
    public OutputStream getOutputStream() throws IOException
    {
//        return super.getOutputStream();
        throw new UnsupportedOperationException();
    }

    @Override
    public SSLSession getSession()
    {
        return engine.getSession();
    }

    @Override
    public SSLParameters getSSLParameters()
    {
        return engine.getSSLParameters();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return engine.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols()
    {
        return engine.getSupportedProtocols();
    }

    @Override
    public boolean getUseClientMode()
    {
        return engine.getUseClientMode();
    }

    @Override
    public boolean getWantClientAuth()
    {
        return engine.getWantClientAuth();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites)
    {
        engine.setEnabledCipherSuites(suites);
    }

    @Override
    public void setEnabledProtocols(String[] protocols)
    {
        engine.setEnabledProtocols(protocols);
    }

    @Override
    public void setEnableSessionCreation(boolean flag)
    {
        engine.setEnableSessionCreation(flag);
    }

    @Override
    public void setNeedClientAuth(boolean need)
    {
        engine.setNeedClientAuth(need);
    }

    @Override
    public void setSSLParameters(SSLParameters params)
    {
        engine.setSSLParameters(params);
    }

    @Override
    public void setUseClientMode(boolean mode)
    {
        engine.setUseClientMode(mode);
    }

    @Override
    public void setWantClientAuth(boolean want)
    {
        engine.setWantClientAuth(want);
    }

    @Override
    public void startHandshake() throws IOException
    {
        /*
         * "This method is synchronous for the initial handshake on a connection and returns when the negotiated handshake is complete."
         */

        // TODO[jsse] Consider checking Thread.interrupted occasionally and aborting with InterruptedIOException accordingly.

        // TODO[jsse]
//        engine.beginHandshake();
//
//        HandshakeStatus status = engine.getHandshakeStatus();
//        while (status != HandshakeStatus.NOT_HANDSHAKING)
//        {
//            switch (status)
//            {
//            case FINISHED:
//                break;
//            case NEED_TASK:
//                break;
//            case NEED_UNWRAP:
//                break;
//            case NEED_WRAP:
//                break;
//            }
//        }

        throw new UnsupportedOperationException();

        // TODO[jsse]
//        if (!listeners.isEmpty())
//        {
//            HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, getSession());
//            synchronized (listeners)
//            {
//                for (HandshakeCompletedListener listener : listeners)
//                {
//                    listener.handshakeCompleted(event);
//                }
//            }
//        }
    }
}
