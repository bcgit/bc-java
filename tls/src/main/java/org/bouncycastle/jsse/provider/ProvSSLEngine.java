package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.RecordFormat;
import org.bouncycastle.tls.RecordPreview;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

/*
 * TODO[jsse] Known limitations (relative to SSLEngine javadoc): 1. The wrap() and unwrap() methods
 * are synchronized, so will not execute concurrently with each other. 2. Never delegates tasks i.e.
 * getDelegatedTasks() will always return null; CPU-intensive parts of the handshake will execute
 * during wrap/unwrap calls.
 */
class ProvSSLEngine
    extends SSLEngine
    implements BCSSLEngine, ProvTlsManager
{
    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;

    protected ProvSSLParameters sslParameters;
    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = true;

    protected boolean initialHandshakeBegun = false;
    protected HandshakeStatus handshakeStatus = HandshakeStatus.NOT_HANDSHAKING; 
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected BCSSLConnection connection = null;
    protected SSLSession handshakeSession = null;

    protected SSLException deferredException = null;

    protected ProvSSLEngine(ProvSSLContextSpi context, ContextData contextData)
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLEngine(ProvSSLContextSpi context, ContextData contextData, String host, int port)
    {
        super(host, port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);;
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
    public synchronized void beginHandshake()
        throws SSLException
    {
        if (initialHandshakeBegun)
        {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }

        this.initialHandshakeBegun = true;

        // TODO[jsse] Check for session to re-use and apply to handshake
        // TODO[jsse] Allocate this.handshakeSession and update it during handshake

        try
        {
            if (this.useClientMode)
            {
                TlsClientProtocol clientProtocol = new TlsClientProtocol();
                this.protocol = clientProtocol;

                ProvTlsClient client = new ProvTlsClient(this);
                this.protocolPeer = client;

                clientProtocol.connect(client);
                this.handshakeStatus = HandshakeStatus.NEED_WRAP;
            }
            else
            {
                TlsServerProtocol serverProtocol = new TlsServerProtocol();
                this.protocol = serverProtocol;

                ProvTlsServer server = new ProvTlsServer(this);
                this.protocolPeer = server;

                serverProtocol.accept(server);
                this.handshakeStatus = HandshakeStatus.NEED_UNWRAP;
            }
        }
        catch (SSLException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            throw new SSLException(e);
        }
    }

    @Override
    public synchronized void closeInbound()
        throws SSLException
    {
        // TODO How to behave when protocol is still null?
        try
        {
            protocol.closeInput();
        }
        catch (IOException e)
        {
            throw new SSLException(e);
        }
    }

    @Override
    public synchronized void closeOutbound()
    {
        // TODO How to behave when protocol is still null?
        try
        {
            protocol.close();
        }
        catch (IOException e)
        {
           // TODO[logging] 
        }
    }

    public synchronized BCSSLConnection getConnection()
    {
        return connection;
    }

    @Override
    public synchronized Runnable getDelegatedTask()
    {
        return null;
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
        // TODO[jsse] this.handshakeSession needs to be reset (to null) whenever not handshaking

        return handshakeSession;
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        return handshakeStatus;
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public synchronized SSLSession getSession()
    {
        return connection == null ? ProvSSLSessionImpl.NULL_SESSION.getExportSession() : connection.getSession();
    }

    @Override
    public synchronized SSLParameters getSSLParameters()
    {
        return SSLParametersUtil.toSSLParameters(sslParameters);
    }

    public synchronized ProvSSLParameters getProvSSLParameters()
    {
        return sslParameters;
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
    public synchronized boolean isInboundDone()
    {
        return protocol != null && protocol.isClosed();
    }

    @Override
    public synchronized boolean isOutboundDone()
    {
        return protocol != null && protocol.isClosed() && protocol.getAvailableOutputBytes() < 1;
    }

    @Override
    public synchronized void setEnabledCipherSuites(String[] suites)
    {
        if (!context.isSupportedCipherSuites(suites))
        {
            throw new IllegalArgumentException("'suites' cannot be null, or contain unsupported cipher suites");
        }

        sslParameters.setCipherSuites(suites);
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols)
    {
        if (!context.isSupportedProtocols(protocols))
        {
            throw new IllegalArgumentException("'protocols' cannot be null, or contain unsupported protocols");
        }

        sslParameters.setProtocols(protocols);
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag)
    {
        this.enableSessionCreation = flag;
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        this.sslParameters = SSLParametersUtil.toProvSSLParameters(sslParameters);
    }

    @Override
    public synchronized void setUseClientMode(boolean mode)
    {
        if (initialHandshakeBegun && mode != this.useClientMode)
        {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        }

        this.useClientMode = mode;
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException
    {
        // TODO[jsse] Argument checks - see javadoc

        if (!initialHandshakeBegun)
        {
            beginHandshake();
        }

        Status resultStatus = Status.OK;
        int bytesConsumed = 0, bytesProduced = 0;

        if (protocol.isClosed())
        {
            resultStatus = Status.CLOSED;
        }
        else
        {
            try
            {
                RecordPreview preview = getRecordPreview(src);
                if (preview == null || src.remaining() < preview.getRecordSize())
                {
                    resultStatus = Status.BUFFER_UNDERFLOW;
                }
                else if (getTotalRemaining(dsts) < (long)preview.getApplicationDataLimit())
                {
                    resultStatus = Status.BUFFER_OVERFLOW;
                }
                else
                {
                    byte[] record = new byte[preview.getRecordSize()];
                    src.get(record);

                    protocol.offerInput(record);
                    bytesConsumed += record.length;

                    int appDataAvailable = protocol.getAvailableInputBytes();
                    for (int dstIndex = 0; dstIndex < length && appDataAvailable > 0; ++dstIndex)
                    {
                        ByteBuffer dst = dsts[dstIndex];
                        int count = Math.min(dst.remaining(), appDataAvailable);
                        if (count > 0)
                        {
                            byte[] appData = new byte[count];
                            int numRead = protocol.readInput(appData, 0, count);
                            assert numRead == count;
                
                            dst.put(appData);
                
                            bytesProduced += count;
                            appDataAvailable -= count;
                        }
                    }

                    // We pre-checked the output would fit, so there should be nothing left over.
                    if (appDataAvailable != 0)
                    {
                        // TODO[tls] Expose a method to fail the connection externally
                        throw new TlsFatalAlert(AlertDescription.record_overflow);
                    }
                }
            }
            catch (IOException e)
            {
                /*
                 * TODO[jsse] 'deferredException' is a workaround for Apache Tomcat's (as of
                 * 8.5.13) SecureNioChannel behaviour when exceptions are thrown from
                 * SSLEngine during the handshake. In the case of SSLEngine.wrap throwing,
                 * Tomcat will call wrap again, allowing any buffered outbound alert to be
                 * flushed. For unwrap, this doesn't happen. So we pretend this unwrap was
                 * OK and ask for NEED_WRAP, then throw in wrap.
                 * 
                 * Note that the SSLEngine javadoc clearly describes a process of flushing
                 * via wrap calls after any closure events, to include thrown exceptions.
                 */
                if (handshakeStatus != HandshakeStatus.NEED_UNWRAP)
                {
                    throw new SSLException(e);
                }

                if (this.deferredException == null)
                {
                    this.deferredException = new SSLException(e);
                }

                handshakeStatus = HandshakeStatus.NEED_WRAP;

                return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, bytesConsumed, bytesProduced);
            }
        }

        /*
         * We only ever change the handshakeStatus here if we started in NEED_UNWRAP
         */
        HandshakeStatus resultHandshakeStatus = handshakeStatus;
        if (handshakeStatus == HandshakeStatus.NEED_UNWRAP)
        {
            if (protocol.getAvailableOutputBytes() > 0)
            {
                handshakeStatus = HandshakeStatus.NEED_WRAP;
                resultHandshakeStatus = HandshakeStatus.NEED_WRAP;
            }
            else if (protocolPeer.isHandshakeComplete())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.FINISHED;
            }
            else if (protocol.isClosed())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
            }
            else
            {
                // Still NEED_UNWRAP
            }
        }

        return new SSLEngineResult(resultStatus, resultHandshakeStatus, bytesConsumed, bytesProduced);
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException
    {
        if (deferredException != null)
        {
            SSLException e = deferredException;
            deferredException = null;
            throw e;
        }

        // TODO[jsse] Argument checks - see javadoc

        if (!initialHandshakeBegun)
        {
            beginHandshake();
        }

        Status resultStatus = Status.OK;
        int bytesConsumed = 0, bytesProduced = 0;

        /*
         * If handshake complete and the connection still open, send the application data in 'srcs'
         */
        if (handshakeStatus == HandshakeStatus.NOT_HANDSHAKING)
        {
            if (protocol.isClosed())
            {
                resultStatus = Status.CLOSED;
            }
            else
            {
                /*
                 * Limit the app data that we will process in one call
                 */
                int srcLimit = ProvSSLSessionImpl.NULL_SESSION.getApplicationBufferSize();

                for (int srcIndex = 0; srcIndex < length && srcLimit > 0; ++srcIndex)
                {
                    ByteBuffer src = srcs[srcIndex];
                    int count = Math.min(src.remaining(), srcLimit);
                    if (count > 0)
                    {
                        byte[] input = new byte[count];
                        src.get(input);
        
                        try
                        {
                            protocol.writeApplicationData(input, 0, count);
                        }
                        catch (IOException e)
                        {
                            // TODO[jsse] Throw a subclass of SSLException?
                            throw new SSLException(e);
                        }

                        bytesConsumed += count;
                        srcLimit -= count;
                    }
                }
            }
        }

        /*
         * Send any available output
         */
        int outputAvailable = protocol.getAvailableOutputBytes();
        if (outputAvailable > 0)
        {
            int count = Math.min(dst.remaining(), outputAvailable);
            if (count > 0)
            {
                byte[] output = new byte[count];
                int numRead = protocol.readOutput(output, 0, count);
                assert numRead == count;
    
                dst.put(output);
    
                bytesProduced += count;
                outputAvailable -= count;
            }

            if (outputAvailable > 0)
            {
                resultStatus = Status.BUFFER_OVERFLOW;
            }
        }

        /*
         * We only ever change the handshakeStatus here if we started in NEED_WRAP
         */
        HandshakeStatus resultHandshakeStatus = handshakeStatus;
        if (handshakeStatus == HandshakeStatus.NEED_WRAP)
        {
            if (outputAvailable > 0)
            {
                // Still NEED_WRAP
            }
            else if (protocolPeer.isHandshakeComplete())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.FINISHED;
            }
            else if (protocol.isClosed())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
            }
            else
            {
                handshakeStatus = HandshakeStatus.NEED_UNWRAP;
                resultHandshakeStatus = HandshakeStatus.NEED_UNWRAP;
                
            }
        }

        return new SSLEngineResult(resultStatus, resultHandshakeStatus, bytesConsumed, bytesProduced);
    }

    public String getPeerHost()
    {
        return super.getPeerHost();
    }

    public int getPeerPort()
    {
        return super.getPeerPort();
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

    private RecordPreview getRecordPreview(ByteBuffer src)
        throws IOException
    {
        if (src.remaining() < RecordFormat.FRAGMENT_OFFSET)
        {
            return null;
        }

        byte[] recordHeader = new byte[RecordFormat.FRAGMENT_OFFSET];

        int position = src.position();
        src.get(recordHeader);
        src.position(position);

        return protocol.previewInputRecord(recordHeader);
    }

    private long getTotalRemaining(ByteBuffer[] buffers)
    {
        long result = 0;
        for (ByteBuffer buffer : buffers)
        {
            result += buffer.remaining();
        }
        return result;
    }
}
