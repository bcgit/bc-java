package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;

/**
 * Base class for a TLS client or server.
 */
public abstract class AbstractTlsPeer
    implements TlsPeer
{
    private final TlsCrypto crypto;

    private volatile TlsCloseable closeHandle;

    protected AbstractTlsPeer(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.downTo(ProtocolVersion.TLSv10);
    }

    protected abstract int[] getSupportedCipherSuites();

    public void cancel() throws IOException
    {
        TlsCloseable closeHandle = this.closeHandle;
        if (null != closeHandle)
        {
            closeHandle.close();
        }
    }

    public TlsCrypto getCrypto()
    {
        return crypto;
    }

    public void notifyCloseHandle(TlsCloseable closeHandle)
    {
        this.closeHandle = closeHandle;
    }

    public void notifyHandshakeBeginning() throws IOException
    {
    }

    public int getHandshakeTimeoutMillis()
    {
        return 0;
    }

    public boolean requiresExtendedMasterSecret()
    {
        return false;
    }

    public boolean shouldCheckSigAlgOfPeerCerts()
    {
        return true;
    }

    public boolean shouldUseExtendedPadding()
    {
        return false;
    }

    public boolean shouldUseGMTUnixTime()
    {
        /*
         * draft-mathewson-no-gmtunixtime-00 2. For the reasons we discuss above, we recommend that
         * TLS implementors MUST by default set the entire value the ClientHello.Random and
         * ServerHello.Random fields, including gmt_unix_time, to a cryptographically random
         * sequence.
         */
        return false;
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {
        if (!secureRenegotiation)
        {
            /*
             * RFC 5746 3.4/3.6. In this case, some clients/servers may want to terminate the handshake instead
             * of continuing; see Section 4.1/4.3 for discussion.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public TlsKeyExchangeFactory getKeyExchangeFactory() throws IOException
    {
        return new DefaultTlsKeyExchangeFactory();
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
    }

    public void notifyHandshakeComplete() throws IOException
    {
    }

    public TlsHeartbeat getHeartbeat()
    {
        return null;
    }

    public short getHeartbeatPolicy()
    {
        return HeartbeatMode.peer_not_allowed_to_send;
    }

    public int getRenegotiationPolicy()
    {
        return RenegotiationPolicy.DENY;
    }
}
