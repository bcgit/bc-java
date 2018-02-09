package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

class ProvSSLSocketWrap
    extends ProvSSLSocketBase
    implements ProvTlsManager
{
    private static Logger LOG = Logger.getLogger(ProvSSLSocketWrap.class.getName());

    private static Socket checkSocket(Socket s) throws SocketException
    {
        if (s == null)
        {
            throw new NullPointerException("'s' cannot be null");
        }
        if (!s.isConnected())
        {
            throw new SocketException("'s' is not a connected socket");
        }
        return s;
    }

    protected final AppDataInput appDataIn = new AppDataInput();
    protected final AppDataOutput appDataOut = new AppDataOutput();

    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;
    protected final Socket wrapSocket;
    protected final InputStream consumed;
    protected final String host;
    protected final boolean autoClose;
    protected final ProvSSLParameters sslParameters;

    protected boolean enableSessionCreation = true;
    protected boolean useClientMode;

    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected BCSSLConnection connection = null;
    protected SSLSession handshakeSession = null;

    protected ProvSSLSocketWrap(ProvSSLContextSpi context, ContextData contextData, Socket s, InputStream consumed, boolean autoClose)
        throws IOException
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.wrapSocket = checkSocket(s);
        this.consumed = consumed;
        this.host = null;
        this.autoClose = autoClose;
        this.useClientMode = false;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    protected ProvSSLSocketWrap(ProvSSLContextSpi context, ContextData contextData, Socket s, String host, int port, boolean autoClose)
        throws IOException
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.wrapSocket = checkSocket(s);
        this.consumed = null;
        this.host = host;
        this.autoClose = autoClose;
        this.useClientMode = true;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    public ProvSSLContextSpi getContext()
    {
        return context;
    }

    public ContextData getContextData()
    {
        return contextData;
    }

    
    @Override
    public void bind(SocketAddress bindpoint) throws IOException
    {
        throw new SocketException("Wrapped socket should already be bound");
    }

    @Override
    public synchronized void close() throws IOException
    {
        if (protocol == null)
        {
            closeSocket();
        }
        else
        {
            protocol.close();
        }
    }

    @Override
    protected void closeSocket() throws IOException
    {
        if (autoClose)
        {
            wrapSocket.close();
        }
        else if (protocol != null)
        {
            /*
             * TODO[jsse] If we initiated the close, we need to wait for the close_notify from the
             * peer to arrive so that the underlying socket can be used after we detach.
             */
        }
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException
    {
        throw new SocketException("Wrapped socket should already be connected");
    }

    @Override
    public SocketChannel getChannel()
    {
        return wrapSocket.getChannel();
    }

    public synchronized BCSSLConnection getConnection()
    {
        try
        {
            handshakeIfNecessary(false);
        }
        catch (Exception e)
        {
            LOG.log(Level.FINE, "Failed to establish connection", e);
        }

        return connection;
    }

    @Override
    public synchronized String[] getEnabledCipherSuites()
    {
        return sslParameters.getCipherSuites();
    }

    @Override
    public synchronized String[] getEnabledProtocols()
    {
        return sslParameters.getProtocols();
    }

    @Override
    public synchronized boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }

    @Override
    public synchronized SSLSession getHandshakeSession()
    {
        return handshakeSession;
    }

    @Override
    public InetAddress getInetAddress()
    {
        return wrapSocket.getInetAddress();
    }

    @Override
    public InputStream getInputStream() throws IOException
    {
        return appDataIn;
    }

    @Override
    public boolean getKeepAlive() throws SocketException
    {
        return wrapSocket.getKeepAlive();
    }

    @Override
    public InetAddress getLocalAddress()
    {
        return wrapSocket.getLocalAddress();
    }

    @Override
    public int getLocalPort()
    {
        return wrapSocket.getLocalPort();
    }

    @Override
    public SocketAddress getLocalSocketAddress()
    {
        return wrapSocket.getLocalSocketAddress();
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public OutputStream getOutputStream() throws IOException
    {
        return appDataOut;
    }

    @Override
    public int getPort()
    {
        return wrapSocket.getPort();
    }

    @Override
    public int getReceiveBufferSize() throws SocketException
    {
        return wrapSocket.getReceiveBufferSize();
    }

    @Override
    public SocketAddress getRemoteSocketAddress()
    {
        return wrapSocket.getRemoteSocketAddress();
    }

    @Override
    public boolean getReuseAddress() throws SocketException
    {
        return wrapSocket.getReuseAddress();
    }

    @Override
    public int getSendBufferSize() throws SocketException
    {
        return wrapSocket.getSendBufferSize();
    }

    @Override
    public synchronized SSLSession getSession()
    {
        BCSSLConnection connection = getConnection();

        return connection == null ? ProvSSLSessionImpl.NULL_SESSION.getExportSession() : connection.getSession();
    }

    @Override
    public int getSoLinger() throws SocketException
    {
        return wrapSocket.getSoLinger();
    }

    @Override
    public int getSoTimeout() throws SocketException
    {
        return wrapSocket.getSoTimeout();
    }

    public synchronized BCSSLParameters getParameters()
    {
        return SSLParametersUtil.getParameters(sslParameters);
    }

    @Override
    public synchronized SSLParameters getSSLParameters()
    {
        return SSLParametersUtil.getSSLParameters(sslParameters);
    }

    @Override
    public synchronized String[] getSupportedCipherSuites()
    {
        return context.getSupportedCipherSuites();
    }

    @Override
    public synchronized String[] getSupportedProtocols()
    {
        return context.getSupportedProtocols();
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException
    {
        return wrapSocket.getTcpNoDelay();
    }

    @Override
    public int getTrafficClass() throws SocketException
    {
        return wrapSocket.getTrafficClass();
    }

    @Override
    public synchronized boolean getUseClientMode()
    {
        return useClientMode;
    }

    @Override
    public synchronized boolean getWantClientAuth()
    {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public boolean isBound()
    {
        return wrapSocket.isBound();
    }

    @Override
    public boolean isConnected()
    {
        return wrapSocket.isConnected();
    }

    @Override
    public synchronized boolean isClosed()
    {
        return protocol != null && protocol.isClosed();
    }

    @Override
    public boolean isInputShutdown()
    {
        return wrapSocket.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown()
    {
        return wrapSocket.isOutputShutdown();
    }

    @Override
    public synchronized void setEnabledCipherSuites(String[] suites)
    {
        sslParameters.setCipherSuites(suites);
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols)
    {
        sslParameters.setProtocols(protocols);
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag)
    {
        this.enableSessionCreation = flag;
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException
    {
        wrapSocket.setKeepAlive(on);
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    public synchronized void setParameters(BCSSLParameters parameters)
    {
        SSLParametersUtil.setParameters(this.sslParameters, parameters);
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
    {
        wrapSocket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException
    {
        wrapSocket.setReceiveBufferSize(size);
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException
    {
        wrapSocket.setReuseAddress(on);
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException
    {
        wrapSocket.setSendBufferSize(size);
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException
    {
        wrapSocket.setSoLinger(on, linger);
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException
    {
        wrapSocket.setSoTimeout(timeout);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters);
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException
    {
        wrapSocket.setTcpNoDelay(on);
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException
    {
        wrapSocket.setTrafficClass(tc);
    }

    @Override
    public synchronized void setUseClientMode(boolean mode)
    {
        if (this.useClientMode == mode)
        {
            return;
        }

        if (protocol != null)
        {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        }

        this.useClientMode = mode;

        context.updateDefaultProtocols(sslParameters, !useClientMode);
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public synchronized void startHandshake() throws IOException
    {
        startHandshake(true);
    }

    protected void startHandshake(boolean resumable) throws IOException
    {
        if (protocol == null)
        {
            // TODO[jsse] Check for session to re-use and apply to handshake
            // TODO[jsse] Allocate this.handshakeSession and update it during handshake

            InputStream input = wrapSocket.getInputStream();
            if (consumed != null)
            {
                input = new SequenceInputStream(consumed, input);
            }

            OutputStream output = wrapSocket.getOutputStream();

            if (this.useClientMode)
            {
                TlsClientProtocol clientProtocol = new ProvTlsClientProtocol(input, output, socketCloser);
                clientProtocol.setResumableHandshake(resumable);
                this.protocol = clientProtocol;

                ProvTlsClient client = new ProvTlsClient(this, sslParameters.copy());
                this.protocolPeer = client;

                clientProtocol.connect(client);
            }
            else
            {
                TlsServerProtocol serverProtocol = new ProvTlsServerProtocol(input, output, socketCloser);
                serverProtocol.setResumableHandshake(resumable);
                this.protocol = serverProtocol;

                ProvTlsServer server = new ProvTlsServer(this, sslParameters.copy());
                this.protocolPeer = server;

                serverProtocol.accept(server);
            }
        }
        else if (protocol.isHandshaking())
        {
            protocol.setResumableHandshake(resumable);
            protocol.resumeHandshake();
        }
        else
        {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }
    }

    @Override
    public String toString()
    {
        // TODO[jsse] Proper toString for sockets
        return wrapSocket.toString();
    }

    public String getPeerHost()
    {
        // TODO[jsse] See SunJSSE for some attempt at implicit host name determination

        return host;
    }

    public int getPeerPort()
    {
        return getPort();
    }

    public boolean isClientTrusted(X509Certificate[] chain, String authType)
    {
        // TODO[jsse] Consider X509ExtendedTrustManager and/or HostnameVerifier functionality

        X509TrustManager tm = contextData.getTrustManager();
        if (tm != null)
        {
            try
            {
                tm.checkClientTrusted(chain, authType);
                return true;
            }
            catch (CertificateException e)
            {
            }
        }
        return false;
    }

    public boolean isServerTrusted(X509Certificate[] chain, String authType)
    {
        // TODO[jsse] Consider X509ExtendedTrustManager and/or HostnameVerifier functionality

        X509TrustManager tm = contextData.getTrustManager();
        if (tm != null)
        {
            try
            {
                tm.checkServerTrusted(chain, authType);
                return true;
            }
            catch (CertificateException e)
            {
            }
        }
        return false;
    }

    public synchronized void notifyHandshakeComplete(ProvSSLConnection connection)
    {
        this.connection = connection;
    }

    synchronized void handshakeIfNecessary(boolean resumable) throws IOException
    {
        if (protocol == null || protocol.isHandshaking())
        {
            startHandshake(resumable);
        }
    }

    class AppDataInput extends InputStream
    {
        @Override
        public int available() throws IOException
        {
            synchronized (ProvSSLSocketWrap.this)
            {
                return protocol == null
                    ?   0
                    :   protocol.applicationDataAvailable();
            }
        }

        @Override
        public void close() throws IOException
        {
            ProvSSLSocketWrap.this.close();
        }

        @Override
        public int read() throws IOException
        {
            handshakeIfNecessary(true);

            byte[] buf = new byte[1];
            int ret = protocol.readApplicationData(buf, 0, 1);
            return ret < 0 ? -1 : buf[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException
        {
            if (len < 1)
            {
                return 0;
            }

            handshakeIfNecessary(true);
            return protocol.readApplicationData(b, off, len);
        }
    }

    class AppDataOutput extends OutputStream
    {
        @Override
        public void close() throws IOException
        {
            ProvSSLSocketWrap.this.close();
        }

        @Override
        public void flush() throws IOException
        {
            synchronized (ProvSSLSocketWrap.this)
            {
                if (protocol != null)
                {
                    protocol.flush();
                }
            }
        }

        @Override
        public void write(int b) throws IOException
        {
            handshakeIfNecessary(true);

            byte[] buf = new byte[]{ (byte)b };
            protocol.writeApplicationData(buf, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException
        {
            if (len > 0)
            {
                handshakeIfNecessary(true);
                protocol.writeApplicationData(b, off, len);
            }
        }
    }
}
