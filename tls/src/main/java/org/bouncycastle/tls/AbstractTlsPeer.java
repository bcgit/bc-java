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

    protected AbstractTlsPeer(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public TlsCrypto getCrypto()
    {
        return crypto;
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

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
    }

    public void notifyHandshakeComplete() throws IOException
    {
    }
}
