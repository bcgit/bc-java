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
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCApplicationProtocolSelector;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

class ProvSSLSocketWrap
    extends ProvSSLSocketBase
    implements ProvTlsManager
{
    private static final Logger LOG = Logger.getLogger(ProvSSLSocketWrap.class.getName());

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

    protected final ContextData contextData;
    protected final Socket wrapSocket;
    protected final InputStream consumed;
    protected final boolean autoClose;
    protected final ProvSSLParameters sslParameters;

    protected String peerHost = null;
    protected String peerHostSNI = null;
    protected boolean enableSessionCreation = true;
    protected boolean useClientMode;

    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected ProvSSLConnection connection = null;
    protected ProvSSLSessionHandshake handshakeSession = null;

    protected ProvSSLSocketWrap(ContextData contextData, Socket s, InputStream consumed, boolean autoClose)
        throws IOException
    {
        this.contextData = contextData;
        this.wrapSocket = checkSocket(s);
        this.consumed = consumed;
        this.autoClose = autoClose;
        this.useClientMode = false;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(useClientMode);

        notifyConnected();
    }

    protected ProvSSLSocketWrap(ContextData contextData, Socket s, String host, int port, boolean autoClose)
        throws IOException
    {
        this.contextData = contextData;
        this.wrapSocket = checkSocket(s);
        this.consumed = null;
        this.peerHost = host;
        this.autoClose = autoClose;
        this.useClientMode = true;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(useClientMode);

        notifyConnected();
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

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws IOException
    {
        try
        {
            contextData.getX509TrustManager().checkClientTrusted(chain.clone(), authType, this);
        }
        catch (CertificateException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws IOException
    {
        try
        {
            contextData.getX509TrustManager().checkServerTrusted(chain.clone(), authType, this);
        }
        catch (CertificateException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public BCX509Key chooseClientKey(String[] keyTypes, Principal[] issuers)
    {
        return getContextData().getX509KeyManager().chooseClientKeyBC(keyTypes, JsseUtils.clone(issuers), this);
    }

    public BCX509Key chooseServerKey(String keyType, Principal[] issuers)
    {
        return getContextData().getX509KeyManager().chooseServerKeyBC(keyType, JsseUtils.clone(issuers), this);
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
    protected void finalize() throws Throwable
    {
        try
        {
            close();
        }
        catch (IOException e)
        {
            // Ignore
        }
        finally
        {
            super.finalize();
        }
    }

    // An SSLSocket method from JDK 9, but also a BCSSLSocket method
    public synchronized String getApplicationProtocol()
    {
        return null == connection ? null : connection.getApplicationProtocol();
    }

    public synchronized BCApplicationProtocolSelector<SSLSocket> getBCHandshakeApplicationProtocolSelector()
    {
        return sslParameters.getSocketAPSelector();
    }

    public synchronized BCExtendedSSLSession getBCHandshakeSession()
    {
        return handshakeSession;
    }

    public BCExtendedSSLSession getBCSession()
    {
        return getSessionImpl();
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

    // An SSLSocket method from JDK 9, but also a BCSSLSocket method
    public synchronized String getHandshakeApplicationProtocol()
    {
        return null == handshakeSession ? null : handshakeSession.getApplicationProtocol();
    }

    // An SSLSocket method from JDK 7
    public synchronized SSLSession getHandshakeSession()
    {
        return null == handshakeSession ? null : handshakeSession.getExportSSLSession();
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
    public SSLSession getSession()
    {
        return getSessionImpl().getExportSSLSession();
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

    // An SSLSocket method from JDK 6
    public synchronized SSLParameters getSSLParameters()
    {
        return SSLParametersUtil.getSSLParameters(sslParameters);
    }

    @Override
    public synchronized String[] getSupportedCipherSuites()
    {
        return contextData.getContext().getSupportedCipherSuites();
    }

    @Override
    public synchronized String[] getSupportedProtocols()
    {
        return contextData.getContext().getSupportedProtocols();
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

    public synchronized void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLSocket> selector)
    {
        sslParameters.setSocketAPSelector(selector);
    }

    public synchronized void setBCSessionToResume(BCExtendedSSLSession session)
    {
        if (null == session)
        {
            throw new NullPointerException("'session' cannot be null");
        }
        if (!(session instanceof ProvSSLSession))
        {
            throw new IllegalArgumentException("Session-to-resume must be a session returned from 'getBCSession'");
        }
        if (null != protocol)
        {
            throw new IllegalArgumentException("Session-to-resume cannot be set after the handshake has begun");
        }

        sslParameters.setSessionToResume((ProvSSLSession)session);
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

    public synchronized void setHost(String host)
    {
        this.peerHost = host;
        this.peerHostSNI = host;
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

    // An SSLSocket method from JDK 6
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
    public synchronized void setUseClientMode(boolean useClientMode)
    {
        if (null != protocol)
        {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        }

        if (this.useClientMode != useClientMode)
        {
            contextData.getContext().updateDefaultSSLParameters(sslParameters, useClientMode);

            this.useClientMode = useClientMode;
        }
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public void shutdownInput() throws IOException
    {
        wrapSocket.shutdownInput();
    }

    @Override
    public void shutdownOutput() throws IOException
    {
        wrapSocket.shutdownOutput();
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

                ProvTlsClient client = new ProvTlsClient(this, sslParameters);
                this.protocolPeer = client;

                clientProtocol.connect(client);
            }
            else
            {
                TlsServerProtocol serverProtocol = new ProvTlsServerProtocol(input, output, socketCloser);
                serverProtocol.setResumableHandshake(resumable);
                this.protocol = serverProtocol;

                ProvTlsServer server = new ProvTlsServer(this, sslParameters);
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

    public synchronized String getPeerHost()
    {
        return peerHost;
    }

    public synchronized String getPeerHostSNI()
    {
        return peerHostSNI;
    }

    public int getPeerPort()
    {
        return getPort();
    }

    public synchronized void notifyHandshakeComplete(ProvSSLConnection connection)
    {
        if (null != handshakeSession)
        {
            if (!handshakeSession.isValid())
            {
                connection.getSession().invalidate();
            }

            handshakeSession.getJsseSecurityParameters().clear();
        }

        this.handshakeSession = null;
        this.connection = connection;

        notifyHandshakeCompletedListeners(connection.getSession().exportSSLSession);
    }

    public synchronized void notifyHandshakeSession(ProvSSLSessionContext sslSessionContext,
        SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters,
        ProvSSLSession resumedSession)
    {
        String peerHost = getPeerHost();
        int peerPort = getPeerPort();

        if (null != resumedSession)
        {
            this.handshakeSession = new ProvSSLSessionResumed(sslSessionContext, peerHost, peerPort, securityParameters,
                jsseSecurityParameters, resumedSession.getTlsSession(), resumedSession.getJsseSessionParameters());
        }
        else
        {
            this.handshakeSession = new ProvSSLSessionHandshake(sslSessionContext, peerHost, peerPort,
                securityParameters, jsseSecurityParameters);
        }
    }

    public synchronized String selectApplicationProtocol(List<String> protocols)
    {
        return sslParameters.getSocketAPSelector().select(this, protocols);
    }

    synchronized ProvSSLSession getSessionImpl()
    {
        getConnection();

        return null == connection ? ProvSSLSession.NULL_SESSION : connection.getSession();
    }

    synchronized void handshakeIfNecessary(boolean resumable) throws IOException
    {
        if (protocol == null || protocol.isHandshaking())
        {
            startHandshake(resumable);
        }
    }

    synchronized void notifyConnected()
    {
        if (null != peerHost && peerHost.length() > 0)
        {
            this.peerHostSNI = peerHost;
            return;
        }

        InetAddress peerAddress = getInetAddress();
        if (null == peerAddress)
        {
            return;
        }

        /*
         * TODO[jsse] If we could somehow access the 'originalHostName' of peerAddress, it would be
         * usable as a default SNI host_name.
         */
//        String originalHostName = null;
//        if (null != originalHostName)
//        {
//            this.peerHost = originalHostName;
//            this.peerHostSNI = originalHostName;
//            return;
//        }

        if (useClientMode && provJdkTlsTrustNameService)
        {
            this.peerHost = peerAddress.getHostName();
        }
        else
        {
            this.peerHost = peerAddress.getHostAddress();
        }

        this.peerHostSNI = null;
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
        public void write(int b) throws IOException
        {
            write(new byte[]{ (byte)b }, 0, 1);
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
