package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCApplicationProtocolSelector;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.RecordFormat;
import org.bouncycastle.tls.RecordPreview;
import org.bouncycastle.tls.SecurityParameters;
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
    private static final Logger LOG = Logger.getLogger(ProvSSLEngine.class.getName());

    protected final ContextData contextData;
    protected final ProvSSLParameters sslParameters;

    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = true;
    protected boolean useClientModeSet = false;

    protected boolean closedEarly = false;
    protected boolean initialHandshakeBegun = false;
    protected boolean returnedFinished = false;
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected ProvSSLConnection connection = null;
    protected ProvSSLSessionHandshake handshakeSession = null;

    protected SSLException deferredException = null;

    protected ProvSSLEngine(ContextData contextData)
    {
        this(contextData, null, -1);
    }

    protected ProvSSLEngine(ContextData contextData, String peerHost, int peerPort)
    {
        super(peerHost, peerPort);

        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(useClientMode);
    }

    public ContextData getContextData()
    {
        return contextData;
    }

    @Override
    public synchronized void beginHandshake()
        throws SSLException
    {
        if (!useClientModeSet)
        {
            throw new IllegalStateException("Client/Server mode must be set before the handshake can begin");
        }
        if (closedEarly)
        {
            throw new SSLException("Connection is already closed");
        }
        if (initialHandshakeBegun)
        {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }

        this.initialHandshakeBegun = true;

        try
        {
            if (this.useClientMode)
            {
                TlsClientProtocol clientProtocol = new TlsClientProtocol();
                this.protocol = clientProtocol;

                ProvTlsClient client = new ProvTlsClient(this, sslParameters);
                this.protocolPeer = client;

                clientProtocol.connect(client);
            }
            else
            {
                TlsServerProtocol serverProtocol = new TlsServerProtocol();
                this.protocol = serverProtocol;

                ProvTlsServer server = new ProvTlsServer(this, sslParameters);
                this.protocolPeer = server;

                serverProtocol.accept(server);
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
        return getContextData().getX509KeyManager().chooseEngineClientKeyBC(keyTypes, JsseUtils.clone(issuers), this);
    }

    public BCX509Key chooseServerKey(String[] keyTypes, Principal[] issuers)
    {
        return getContextData().getX509KeyManager().chooseEngineServerKeyBC(keyTypes, JsseUtils.clone(issuers), this);
    }

    @Override
    public synchronized void closeInbound()
        throws SSLException
    {
        if (closedEarly)
        {
            // SSLEngine already closed before any handshake attempted
        }
        else if (null == protocol)
        {
            this.closedEarly = true;
        }
        else
        {
            try
            {
                protocol.closeInput();
            }
            catch (IOException e)
            {
                throw new SSLException(e);
            }
        }
    }

    @Override
    public synchronized void closeOutbound()
    {
        if (closedEarly)
        {
            // SSLEngine already closed before any handshake attempted
        }
        else if (null == protocol)
        {
            this.closedEarly = true;
        }
        else
        {
            try
            {
                protocol.close();
            }
            catch (IOException e)
            {
                LOG.log(Level.WARNING, "Failed to close outbound", e);
            }
        }
    }

    // An SSLEngine method from JDK 9 (and then 8u251), but also a BCSSLEngine method
    public synchronized String getApplicationProtocol()
    {
        return null == connection ? null : connection.getApplicationProtocol();
    }

    public synchronized BCApplicationProtocolSelector<SSLEngine> getBCHandshakeApplicationProtocolSelector()
    {
        return sslParameters.getEngineAPSelector();
    }

    public synchronized BCExtendedSSLSession getBCHandshakeSession()
    {
        return handshakeSession;
    }

    public BCExtendedSSLSession getBCSession()
    {
        return getSessionImpl();
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

    // An SSLEngine method from JDK 9 (and then 8u251), but also a BCSSLEngine method
    public synchronized String getHandshakeApplicationProtocol()
    {
        return null == handshakeSession ? null : handshakeSession.getApplicationProtocol();
    }

    // An SSLEngine method from JDK 7
    public synchronized SSLSession getHandshakeSession()
    {
        return null == handshakeSession ? null : handshakeSession.getExportSSLSession();
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        if (protocol != null)
        {
            if (protocol.getAvailableOutputBytes() > 0 || deferredException != null)
            {
                return HandshakeStatus.NEED_WRAP;
            }
            if (protocol.isHandshaking())
            {
                return HandshakeStatus.NEED_UNWRAP;
            }
        }
        return HandshakeStatus.NOT_HANDSHAKING;
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    public synchronized BCSSLParameters getParameters()
    {
        return SSLParametersUtil.getParameters(sslParameters);
    }

    @Override
    public SSLSession getSession()
    {
        return getSessionImpl().getExportSSLSession();
    }

    // An SSLEngine method from JDK 6
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

    public int getTransportID()
    {
        return System.identityHashCode(this);
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
        return closedEarly || (null != protocol && protocol.isClosed());
    }

    @Override
    public synchronized boolean isOutboundDone()
    {
        return closedEarly || (null != protocol && protocol.isClosed() && protocol.getAvailableOutputBytes() < 1);
    }

    public synchronized void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLEngine> selector)
    {
        sslParameters.setEngineAPSelector(selector);
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
        if (initialHandshakeBegun)
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

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    public synchronized void setParameters(BCSSLParameters parameters)
    {
        SSLParametersUtil.setParameters(this.sslParameters, parameters);
    }

    // An SSLEngine method from JDK 6
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters);
    }

    @Override
    public synchronized void setUseClientMode(boolean useClientMode)
    {
        if (initialHandshakeBegun)
        {
            throw new IllegalArgumentException("Client/Server mode cannot be changed after the handshake has begun");
        }

        if (this.useClientMode != useClientMode)
        {
            contextData.getContext().updateDefaultSSLParameters(sslParameters, useClientMode);

            this.useClientMode = useClientMode;
        }

        this.useClientModeSet = true;
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

        final HandshakeStatus initialHandshakeStatus = getHandshakeStatus();

        if (isInboundDone())
        {
            return new SSLEngineResult(Status.CLOSED, initialHandshakeStatus, 0, 0);
        }

        if (!initialHandshakeBegun)
        {
            beginHandshake();
        }

        switch (initialHandshakeStatus)
        {
        case NEED_UNWRAP:
        case NOT_HANDSHAKING:
            break;
        default:
            return new SSLEngineResult(Status.OK, initialHandshakeStatus, 0, 0);
        }

        int bytesConsumed = 0;
        try
        {
            RecordPreview preview = getRecordPreview(src);
            if (preview == null || src.remaining() < preview.getRecordSize())
            {
                return new SSLEngineResult(Status.BUFFER_UNDERFLOW, initialHandshakeStatus, 0, 0);
            }
            if (hasInsufficientSpace(dsts, offset, length, preview.getContentLimit()))
            {
                return new SSLEngineResult(Status.BUFFER_OVERFLOW, initialHandshakeStatus, 0, 0);
            }

            bytesConsumed = preview.getRecordSize();
            byte[] record = new byte[bytesConsumed];
            src.get(record);

            protocol.offerInput(record, 0, record.length);
        }
        catch (IOException e)
        {
            /*
             * TODO[jsse] 'deferredException' is a workaround for Apache Tomcat's (as of 8.5.13)
             * SecureNioChannel behaviour when exceptions are thrown from SSLEngine during the handshake.
             * In the case of SSLEngine.wrap throwing, Tomcat will call wrap again, allowing any buffered
             * outbound alert to be flushed. For unwrap, this doesn't happen. So we capture the exception
             * and ask for NEED_WRAP, then throw in wrap.
             * 
             * Note that the SSLEngine javadoc clearly describes a process of flushing via wrap calls
             * after any closure events, to include thrown exceptions.
             */
            if (initialHandshakeStatus != HandshakeStatus.NEED_UNWRAP)
            {
                throw new SSLException(e);
            }

            this.deferredException = new SSLException(e);

            return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, bytesConsumed, 0);
        }

        int appDataAvailable = protocol.getAvailableInputBytes(), bytesProduced = 0;
        for (int dstIndex = 0; appDataAvailable > 0; ++dstIndex)
        {
            ByteBuffer dst = dsts[offset + dstIndex];
            int count = Math.min(dst.remaining(), appDataAvailable);
            if (count > 0)
            {
                int numRead = protocol.readInput(dst, count);
                assert numRead == count;

                bytesProduced += count;
                appDataAvailable -= count;
            }
        }

        HandshakeStatus resultHandshakeStatus = getHandshakeStatus();
        if (resultHandshakeStatus == HandshakeStatus.NOT_HANDSHAKING)
        {
            if (!returnedFinished && protocolPeer.isHandshakeComplete())
            {
                returnedFinished = true;
                resultHandshakeStatus = HandshakeStatus.FINISHED;
            }
        }

        return new SSLEngineResult(getStatus(), resultHandshakeStatus, bytesConsumed, bytesProduced);
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

        if (closedEarly)
        {
            return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }

        if (!initialHandshakeBegun)
        {
            beginHandshake();
        }

        int bytesProduced = 0;

        final int outputAvailable = protocol.getAvailableOutputBytes();
        if (outputAvailable > 0)
        {
            /*
             * Process record-aligned output; all available if possible, or else just the first record.
             */
            int remaining = dst.remaining();
            if (remaining >= outputAvailable)
            {
                bytesProduced = outputAvailable;
            }
            else
            {
                bytesProduced = protocol.previewOutputRecord();
                assert bytesProduced > 0;

                if (remaining < bytesProduced)
                {
                    return new SSLEngineResult(Status.BUFFER_OVERFLOW, HandshakeStatus.NEED_WRAP, 0, 0);
                }
            }

            int numRead = protocol.readOutput(dst, bytesProduced);
            assert numRead == bytesProduced;

            if (bytesProduced < outputAvailable)
            {
                return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, 0, bytesProduced);
            }

            // NB: Fall through intentional
        }
        else if (protocol.isConnected())
        {
            try
            {
                int bytesConsumed = 0;

                /*
                 * Generate at most one maximum-sized application data record per call.
                 */
                int srcRemaining = getTotalRemaining(srcs, offset, length, protocol.getApplicationDataLimit());
                if (srcRemaining > 0)
                {
                    RecordPreview preview = protocol.previewOutputRecord(srcRemaining);

                    int srcLimit = preview.getContentLimit();
                    int dstLimit = preview.getRecordSize();

                    if (dst.remaining() < dstLimit)
                    {
                        return new SSLEngineResult(Status.BUFFER_OVERFLOW, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
                    }

                    // TODO Support writing application data using ByteBuffer array directly

                    byte[] buffer = new byte[srcLimit];

                    for (int srcIndex = 0; srcIndex < length && bytesConsumed < srcLimit; ++srcIndex)
                    {
                        ByteBuffer src = srcs[offset + srcIndex];
                        int count = Math.min(src.remaining(), srcLimit - bytesConsumed);
                        if (count > 0)
                        {
                            src.get(buffer, bytesConsumed, count);
                            bytesConsumed += count;
                        }
                    }

                    protocol.writeApplicationData(buffer, 0, bytesConsumed);

                    bytesProduced = protocol.getAvailableOutputBytes();
                    assert bytesProduced <= dstLimit;

                    int numRead = protocol.readOutput(dst, bytesProduced);
                    assert numRead == bytesProduced;
                }

                return new SSLEngineResult(getStatus(), HandshakeStatus.NOT_HANDSHAKING, bytesConsumed, bytesProduced);
            }
            catch (IOException e)
            {
                // TODO[jsse] Throw a subclass of SSLException?
                throw new SSLException(e);
            }
        }

        if (protocol.isHandshaking())
        {
            return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_UNWRAP, 0, bytesProduced);
        }

        HandshakeStatus resultHandshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
        if (!returnedFinished && protocolPeer.isHandshakeComplete())
        {
            returnedFinished = true;
            resultHandshakeStatus = HandshakeStatus.FINISHED;
        }

        return new SSLEngineResult(getStatus(), resultHandshakeStatus, 0, bytesProduced);
    }

    public String getPeerHost()
    {
        return super.getPeerHost();
    }

    public String getPeerHostSNI()
    {
        return super.getPeerHost();
    }

    public int getPeerPort()
    {
        return super.getPeerPort();
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
        return sslParameters.getEngineAPSelector().select(this, protocols);
    }

    ProvSSLSession getSessionImpl()
    {
        return null == connection ? ProvSSLSession.NULL_SESSION : connection.getSession();
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

    private Status getStatus()
    {
        return protocol.isClosed() ? Status.CLOSED : Status.OK;
    }

    private int getTotalRemaining(ByteBuffer[] bufs, int off, int len, int limit)
    {
        int result = 0;
        for (int i = 0; i < len; ++i)
        {
            ByteBuffer buf = bufs[off + i];
            int next = buf.remaining();
            if (next >= (limit - result))
            {
                return limit;
            }
            result += next;
        }
        return result;
    }

    private boolean hasInsufficientSpace(ByteBuffer[] dsts, int off, int len, int amount)
    {
        return getTotalRemaining(dsts, off, len, amount) < amount;
    }
}
